//! Rate limits (REQUIREMENTS A4): a bulk read by a stolen credential should look like what it is.
//!
//! A sliding window per caller and action, in memory. With several replicas each keeps its own count, so the
//! real limit is up to the number of replicas times the configured one (PLAN.md M3 step 5: "in memory per
//! replica first"). Counts are lost on restart. Both are stated limits, not oversights.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::policy::Action;

/// The window every limit is counted over.
pub const WINDOW: Duration = Duration::from_secs(3600);

/// What the limiter decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Go ahead. The attempt has been counted.
    Allowed,
    /// Over the limit. Try again after this long.
    Limited {
        /// When the oldest counted attempt leaves the window.
        retry_after: Duration,
    },
}

/// A sliding-window counter per `(caller, action)`.
#[derive(Debug)]
pub struct RateLimiter {
    window: Duration,
    max_keys: usize,
    counts: Mutex<HashMap<(String, Action), VecDeque<Instant>>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(WINDOW, 100_000)
    }
}

impl RateLimiter {
    /// A limiter counting over `window`, remembering at most `max_keys` callers.
    pub fn new(window: Duration, max_keys: usize) -> Self {
        Self {
            window,
            max_keys,
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Counts an attempt unless it would exceed `limit` in the window ending at `now`. A limit of 0 refuses
    /// everything.
    pub fn check(&self, caller: &str, action: Action, limit: u32, now: Instant) -> Verdict {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if counts.len() >= self.max_keys {
            // Forget callers with nothing left in the window before taking a new one.
            counts.retain(|_, q| {
                q.back()
                    .is_some_and(|t| now.saturating_duration_since(*t) < self.window)
            });
        }
        let q = counts.entry((caller.to_owned(), action)).or_default();
        while q
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= self.window)
        {
            q.pop_front();
        }
        if q.len() >= usize::try_from(limit).unwrap_or(usize::MAX) {
            let retry_after = q.front().map_or(self.window, |t| {
                (*t + self.window).saturating_duration_since(now)
            });
            return Verdict::Limited { retry_after };
        }
        q.push_back(now);
        Verdict::Allowed
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn it_counts_per_caller_and_action_and_forgets_after_the_window() {
        let l = RateLimiter::new(secs(100), 1000);
        let t0 = Instant::now();
        for i in 0..3 {
            assert_eq!(
                l.check("a", Action::Read, 3, t0 + secs(i)),
                Verdict::Allowed
            );
        }
        assert_eq!(
            l.check("a", Action::Read, 3, t0 + secs(5)),
            Verdict::Limited {
                retry_after: secs(95)
            }
        );
        // Another caller, and another action, have their own counts.
        assert_eq!(
            l.check("b", Action::Read, 3, t0 + secs(5)),
            Verdict::Allowed
        );
        assert_eq!(
            l.check("a", Action::Shred, 3, t0 + secs(5)),
            Verdict::Allowed
        );
        // The oldest attempt leaves the window at t0 + 100.
        assert!(matches!(
            l.check("a", Action::Read, 3, t0 + secs(99)),
            Verdict::Limited { .. }
        ));
        assert_eq!(
            l.check("a", Action::Read, 3, t0 + secs(100)),
            Verdict::Allowed
        );
        assert!(matches!(
            l.check("a", Action::Read, 3, t0 + secs(100)),
            Verdict::Limited { .. }
        ));
    }

    #[test]
    fn a_refused_attempt_is_not_counted_and_a_zero_limit_refuses_everything() {
        let l = RateLimiter::new(secs(10), 1000);
        let t0 = Instant::now();
        assert_eq!(l.check("a", Action::Read, 1, t0), Verdict::Allowed);
        for i in 1..50 {
            assert!(matches!(
                l.check("a", Action::Read, 1, t0 + Duration::from_millis(i * 100)),
                Verdict::Limited { .. }
            ));
        }
        // Fifty refusals did not push the window out: one slot is free again 10 s after the only counted one.
        assert_eq!(
            l.check("a", Action::Read, 1, t0 + secs(10)),
            Verdict::Allowed
        );
        assert!(matches!(
            l.check("z", Action::Read, 0, t0),
            Verdict::Limited { .. }
        ));
    }

    #[test]
    fn the_number_of_remembered_callers_is_bounded() {
        let l = RateLimiter::new(secs(10), 8);
        let t0 = Instant::now();
        for i in 0..200 {
            l.check(&format!("caller-{i}"), Action::Read, 5, t0 + secs(i));
        }
        let n = l.counts.lock().unwrap().len();
        assert!(n <= 20, "{n} callers are remembered");
    }
}
