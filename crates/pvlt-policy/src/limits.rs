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

/// How often a full limiter may scan for callers it can forget. Between scans a new caller is simply refused, so
/// a flood of new names cannot make every request scan the whole table.
const SWEEP_EVERY: Duration = Duration::from_secs(1);

/// A sliding-window counter per `(caller, action)`.
#[derive(Debug)]
pub struct RateLimiter {
    window: Duration,
    max_keys: usize,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    counts: HashMap<(String, Action), VecDeque<Instant>>,
    last_sweep: Option<Instant>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(WINDOW, 100_000)
    }
}

impl State {
    /// Drops attempts that have left the window from one queue.
    fn trim(q: &mut VecDeque<Instant>, now: Instant, window: Duration) {
        while q
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= window)
        {
            q.pop_front();
        }
    }

    /// Makes room for a new key if the table is full, at most once per [`SWEEP_EVERY`]. Returns whether there
    /// is room.
    fn room(&mut self, max_keys: usize, now: Instant, window: Duration) -> bool {
        if self.counts.len() < max_keys {
            return true;
        }
        let due = self
            .last_sweep
            .is_none_or(|t| now.saturating_duration_since(t) >= SWEEP_EVERY);
        if due {
            self.last_sweep = Some(now);
            self.counts.retain(|_, q| {
                q.back()
                    .is_some_and(|t| now.saturating_duration_since(*t) < window)
            });
        }
        self.counts.len() < max_keys
    }
}

impl RateLimiter {
    /// A limiter counting over `window`, remembering at most `max_keys` callers. When it is full of callers that
    /// are all still inside the window, a caller it does not know yet is refused rather than let through: the
    /// table can never grow past `max_keys`.
    pub fn new(window: Duration, max_keys: usize) -> Self {
        Self {
            window,
            max_keys,
            state: Mutex::new(State::default()),
        }
    }

    /// Counts an attempt unless it would exceed `limit` in the window ending at `now`. A limit of 0 refuses
    /// everything.
    pub fn check(&self, caller: &str, action: Action, limit: u32, now: Instant) -> Verdict {
        self.check_all(&[(caller, action, limit)], now)
    }

    /// Counts one attempt against every `(key, action, limit)` given, or against none of them: if any is over
    /// its limit nothing is counted and the longest wait is returned. This is how a per-caller limit and a
    /// role's total apply to one request without one of them counting a request the other refused.
    pub fn check_all(&self, limits: &[(&str, Action, u32)], now: Instant) -> Verdict {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut wait: Option<Duration> = None;
        for (key, action, limit) in limits {
            let k = ((*key).to_owned(), *action);
            if !state.counts.contains_key(&k) && !state.room(self.max_keys, now, self.window) {
                wait = Some(wait.map_or(SWEEP_EVERY, |w| w.max(SWEEP_EVERY)));
                continue;
            }
            let q = state.counts.entry(k).or_default();
            State::trim(q, now, self.window);
            if q.len() >= usize::try_from(*limit).unwrap_or(usize::MAX) {
                let retry_after = q.front().map_or(self.window, |t| {
                    (*t + self.window).saturating_duration_since(now)
                });
                wait = Some(wait.map_or(retry_after, |w| w.max(retry_after)));
            }
        }
        if let Some(retry_after) = wait {
            return Verdict::Limited { retry_after };
        }
        for (key, action, _) in limits {
            if let Some(q) = state.counts.get_mut(&((*key).to_owned(), *action)) {
                q.push_back(now);
            }
        }
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
        let n = l.state.lock().unwrap().counts.len();
        assert!(n <= 8, "{n} callers are remembered");
    }

    #[test]
    fn a_full_table_of_live_callers_refuses_new_ones_and_never_grows() {
        let l = RateLimiter::new(secs(100), 8);
        let t0 = Instant::now();
        for i in 0..8 {
            assert_eq!(
                l.check(&format!("live-{i}"), Action::Read, 5, t0),
                Verdict::Allowed
            );
        }
        // Every one of the eight is still in the window: a ninth name is refused, a known one still works.
        for i in 0..1000 {
            assert!(matches!(
                l.check(&format!("flood-{i}"), Action::Read, 5, t0 + secs(1)),
                Verdict::Limited { .. }
            ));
        }
        assert_eq!(
            l.check("live-0", Action::Read, 5, t0 + secs(1)),
            Verdict::Allowed
        );
        assert_eq!(l.state.lock().unwrap().counts.len(), 8);
        // Once they leave the window there is room again.
        assert_eq!(
            l.check("new", Action::Read, 5, t0 + secs(200)),
            Verdict::Allowed
        );
    }

    #[test]
    fn check_all_counts_every_key_or_none() {
        let l = RateLimiter::new(secs(100), 1000);
        let t0 = Instant::now();
        // A total of 3 over every caller, and 2 per caller.
        let mut allowed = 0;
        for i in 0..10 {
            let caller = format!("c{}", i % 5);
            if l.check_all(
                &[(&caller, Action::Read, 2), ("total", Action::Read, 3)],
                t0,
            ) == Verdict::Allowed
            {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 3, "the total holds however many callers there are");
        // The per-caller counts did not move for the refused attempts: c4 has used nothing.
        assert_eq!(l.check("c4", Action::Read, 2, t0), Verdict::Allowed);
        assert_eq!(l.check("c4", Action::Read, 2, t0), Verdict::Allowed);
    }
}
