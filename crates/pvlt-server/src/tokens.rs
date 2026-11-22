//! Request tokens (REQUIREMENTS 3.7): short-lived [Biscuit](https://www.biscuitsec.org) tokens that a trusted
//! service mints for one operation, carrying who is acting and in what capacity.
//!
//! This crate only answers "is this token genuine, unexpired and signed by a key I was given, and what does it
//! claim?". **It decides nothing about permission.** What a claim is allowed to mean is the policy's job
//! (`pvlt_policy::policy`), which does not trust a claim just because it is signed.
//!
//! # Claims
//!
//! The authority block (the part only the issuer can write) holds these facts:
//!
//! | Fact | Meaning | Required |
//! |---|---|---|
//! | `expires(<unix seconds>)` | the token is invalid at or after this time | yes |
//! | `request_id("..")` | ties audit entries to the caller's request | yes |
//! | `caller("..")` | who is acting, such as `user:77` | no |
//! | `subject("..")` | the data subject the request is about | no |
//! | `role("..")` | a role the issuer asserts (repeatable) | no |
//! | `purpose("..")`, `reason("..")` | why | no |
//! | `action("..")` | the only actions the token may be used for (repeatable) | no |
//! | `resource_fact("<uuid>")`, `resource_scope("..")`, `resource_subject("..")` | the only resource it may touch | no |
//! | `grant("..")` | a capability granted elsewhere, such as `order_open` (repeatable) | no |
//! | `approval("..")` | the id of a dual-control approval | no |
//!
//! The issuer is identified by the token's root key id, which the registry maps to a public key. A token with no
//! key id, an unknown key id, a bad signature, no `expires`, or an `expires` further than `max_ttl` away is
//! refused. `expires` is read from the authority block before any Datalog runs, so an expired token costs no more
//! than its signatures.
//!
//! # Attenuation
//!
//! Any holder can append blocks, and later blocks can only **narrow** a token: they may hold checks and nothing
//! else. A block after the authority block that holds a fact or a rule is refused, so a holder cannot add a role
//! by attenuating. Every check in a token must pass, at the time `verify` is given.
//!
//! These limits are enforced on the blocks after the authority block before any Datalog runs. A token that goes
//! past any of them is refused as [`TokenError::Rejected`]:
//!
//! | What | Limit |
//! |---|---|
//! | facts and rules | none at all |
//! | checks (`check if`, `check all`, `reject if`) | [`MAX_ATTENUATION_CHECKS`] in all the later blocks together |
//! | `or` alternatives in one check | [`MAX_CHECK_ALTERNATIVES`] |
//! | predicates in one alternative, such as `time($t)` or `action("read")` | [`MAX_QUERY_PREDICATES`] |
//! | size of one alternative: one per predicate term and per expression operation, plus one per element of a set, array or map | [`MAX_QUERY_SIZE`] |
//! | `.all()`, `.any()` and `.matches()` | not allowed |
//!
//! **For issuers and holders:** a narrowing check over three or more claims has to be split into separate checks.
//! `check if time($t), action("read"), resource_scope("kyc-doc:42"), $t < 2026-01-01T00:00:00Z` is refused;
//! `check if time($t), $t < 2026-01-01T00:00:00Z; check if action("read"); check if resource_scope("kyc-doc:42");`
//! says the same and passes. Splitting only changes the meaning when one expression compares values from three
//! claims at once, and no claim here needs that.
//!
//! Why: biscuit-auth reads its time limit only between check queries and between rounds of rules, and its fact
//! limit only after a whole round. A single query that joins many predicates, or loops over a collection with
//! `.all()` / `.any()`, or compiles a regex for every match, runs to the end whatever the limits say. These rules
//! keep every query a holder can add small, so the time limit can stop a long run of them.

use core::fmt;
use core::time::Duration;

use biscuit_auth::builder::{
    Algorithm, AuthorizerBuilder, Binary, BiscuitBuilder, BlockBuilder, Fact, Op, Rule, Term,
};
use biscuit_auth::{
    AuthorizerLimits, Biscuit, KeyPair, PrivateKey, PublicKey, RootKeyProvider, error,
};
use uuid::Uuid;

/// The longest token text accepted, before any parsing.
pub const MAX_TOKEN_LEN: usize = 8 * 1024;
/// The longest a single claim string may be.
pub const MAX_CLAIM_LEN: usize = 256;
/// The most values a repeatable claim may have.
pub const MAX_REPEATS: usize = 32;

// Run limits for a token's Datalog. Blocks a holder adds hold only checks, each kept small by the attenuation
// limits below, so what these limits stop is a long run of such checks, and rules in the authority block. A
// genuine token holds about a hundred facts at most (ten single claims, three repeatable ones up to
// `MAX_REPEATS` each, and `time`) and needs one round of rule evaluation, so the fact and round limits sit far
// above it.
//
// The time limit is wall-clock time, so it also counts time the thread spends waiting for a CPU. biscuit-auth's
// default of 1 ms refused genuine tokens when the machine was busy: with 32 threads verifying a token that
// carries every claim, about 1 in 8 were refused in a debug build. 50 ms tolerates that and still bounds a block
// that keeps deriving facts round after round. biscuit-auth reads the clock only between rounds and between
// check queries, so a single costly round or a check with a large join can run past it. That is why blocks after
// the authority block are bounded before anything runs.
/// The most facts a token's Datalog may hold before it is refused.
pub const MAX_FACTS: u64 = 1000;
/// The most rounds of rule evaluation a token may need before it is refused.
pub const MAX_ITERATIONS: u64 = 100;
/// The longest the token's rules and checks may run, together, before it is refused.
pub const MAX_TIME: Duration = Duration::from_millis(50);

// Attenuation limits, enforced on every block after the authority block before any Datalog runs (see the module
// docs). A check in a later block can join only the authority block's facts and `time`: at most `MAX_REPEATS` of
// each claim in a genuine token. Two predicates over a full token is 32 x 32 = 1024 matches, measured at 7.5 ms in
// a debug build; three would be 32 768, at 127 ms, for a single query that the time limit cannot interrupt.
/// The most checks all the blocks after the authority block may hold together.
pub const MAX_ATTENUATION_CHECKS: usize = 32;
/// The most `or` alternatives one check in a later block may have.
pub const MAX_CHECK_ALTERNATIVES: usize = 4;
/// The most predicates one alternative of a check in a later block may join.
pub const MAX_QUERY_PREDICATES: usize = 2;
/// The largest one alternative of a check in a later block may be: one per predicate term and per expression
/// operation, plus one per element of a set, array or map.
pub const MAX_QUERY_SIZE: usize = 64;

fn run_limits() -> AuthorizerLimits {
    AuthorizerLimits {
        max_facts: MAX_FACTS,
        max_iterations: MAX_ITERATIONS,
        max_time: MAX_TIME,
    }
}

/// Why a token was refused. It never carries the token or any claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Not a token, or too large.
    Malformed,
    /// The signature does not verify, or a check inside the token failed (including attenuation).
    Rejected,
    /// The token has no root key id, or the registry has no key for it.
    UnknownIssuer,
    /// `expires` is in the past.
    Expired,
    /// `expires` is further away than the longest lifetime allowed.
    LifetimeTooLong,
    /// A required claim is missing.
    Missing(&'static str),
    /// A claim has the wrong shape, is repeated when it must not be, or is too long.
    Invalid(&'static str),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::Malformed => f.write_str("malformed token"),
            TokenError::Rejected => f.write_str("token rejected"),
            TokenError::UnknownIssuer => f.write_str("unknown token issuer"),
            TokenError::Expired => f.write_str("token expired"),
            TokenError::LifetimeTooLong => f.write_str("token lifetime too long"),
            TokenError::Missing(c) => write!(f, "token has no {c}"),
            TokenError::Invalid(c) => write!(f, "token claim {c} is invalid"),
        }
    }
}

impl std::error::Error for TokenError {}

/// What a verified token claims.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims {
    /// The registry id of the issuer, from the token's root key id.
    pub issuer_key_id: u32,
    /// Who is acting.
    pub caller: Option<String>,
    /// The data subject.
    pub subject: Option<String>,
    /// Roles the issuer asserts. Not yet checked against what the issuer may assert.
    pub roles: Vec<String>,
    /// Why, as a short code.
    pub purpose: Option<String>,
    /// Why, in a few words.
    pub reason: Option<String>,
    /// The caller's request id.
    pub request_id: String,
    /// The actions the token is limited to. Empty means no limit from the token.
    pub actions: Vec<String>,
    /// The one fact it may touch.
    pub resource_fact: Option<Uuid>,
    /// The one scope it may touch.
    pub resource_scope: Option<String>,
    /// The one subject it may touch.
    pub resource_subject: Option<String>,
    /// Capabilities granted elsewhere.
    pub grants: Vec<String>,
    /// A dual-control approval id.
    pub approval: Option<String>,
    /// When it stops being valid, in unix seconds.
    pub expires: i64,
}

/// The registry of issuer public keys.
pub trait IssuerKeys {
    /// The Ed25519 public key for a root key id, if one is registered and enabled.
    fn public_key(&self, key_id: u32) -> Option<[u8; 32]>;
}

struct Provider<'a, K>(&'a K);

impl<K: IssuerKeys> RootKeyProvider for Provider<'_, K> {
    fn choose(&self, key_id: Option<u32>) -> Result<PublicKey, error::Format> {
        let id = key_id.ok_or(error::Format::UnknownPublicKey)?;
        let bytes = self
            .0
            .public_key(id)
            .ok_or(error::Format::UnknownPublicKey)?;
        PublicKey::from_bytes(&bytes, Algorithm::Ed25519)
    }
}

fn rfc3339(unix: i64) -> Result<String, TokenError> {
    let t =
        time::OffsetDateTime::from_unix_timestamp(unix).map_err(|_| TokenError::Invalid("time"))?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    ))
}

/// Reads one claim after `authorize`, from the authority block only (a query never sees later blocks' facts).
///
/// `Authorizer::query` charges each query to the time already spent in `authorize` and refuses once the total
/// reaches `MAX_TIME`, so a dozen queries could run out the budget of a token that had already passed. Each claim
/// query is a single pass of a one-predicate rule over facts that are already computed, with no rounds and no
/// joins, so it is given limits of its own instead. (biscuit-auth 6.0 does not apply limits inside a query at
/// all, and does not charge it against the earlier total.)
fn claim_query<T>(
    authorizer: &mut biscuit_auth::Authorizer,
    rule: &str,
) -> Result<Vec<T>, TokenError>
where
    T: TryFrom<Fact, Error = error::Token>,
{
    authorizer
        .query_with_limits(rule, run_limits())
        .map_err(|_| TokenError::Rejected)
}

fn strings(
    authorizer: &mut biscuit_auth::Authorizer,
    name: &'static str,
) -> Result<Vec<String>, TokenError> {
    let rule = format!("data($x) <- {name}($x)");
    let found: Vec<(String,)> = claim_query(authorizer, &rule)?;
    let mut out: Vec<String> = found.into_iter().map(|(s,)| s).collect();
    out.sort();
    out.dedup();
    if out.len() > MAX_REPEATS || out.iter().any(|s| s.len() > MAX_CLAIM_LEN) {
        return Err(TokenError::Invalid(name));
    }
    Ok(out)
}

fn at_most_one(mut v: Vec<String>, name: &'static str) -> Result<Option<String>, TokenError> {
    match v.len() {
        0 => Ok(None),
        1 => Ok(v.pop()),
        _ => Err(TokenError::Invalid(name)),
    }
}

fn check_lifetime(expires: i64, now: i64, max_ttl: i64) -> Result<(), TokenError> {
    if expires <= now {
        return Err(TokenError::Expired);
    }
    if expires.saturating_sub(now) > max_ttl {
        return Err(TokenError::LifetimeTooLong);
    }
    Ok(())
}

/// One block of a token, read back as Datalog. biscuit-auth keeps its parsed blocks private, so the block is
/// printed and parsed again; a block that does not survive that is not one this module can bound.
fn block_code(biscuit: &Biscuit, index: usize) -> Option<BlockBuilder> {
    let source = biscuit.print_block_source(index).ok()?;
    BlockBuilder::new().code(source).ok()
}

/// Refuses an expired or too long-lived token from the authority block's `expires` fact alone, before any Datalog
/// runs, so only the holder of a live token can make the vault run a block they added. A missing or repeated
/// `expires` is left to the read after `authorize`, which reports it.
fn expiry_first(biscuit: &Biscuit, now: i64, max_ttl: i64) -> Result<(), TokenError> {
    let Some(authority) = block_code(biscuit, 0) else {
        return Ok(());
    };
    let mut found = authority
        .facts
        .iter()
        .filter(|f| f.predicate.name == "expires");
    if let (Some(fact), None) = (found.next(), found.next())
        && let [Term::Integer(expires)] = fact.predicate.terms.as_slice()
    {
        check_lifetime(*expires, now, max_ttl)?;
    }
    Ok(())
}

fn term_size(term: &Term) -> usize {
    match term {
        Term::Set(set) => set.iter().map(term_size).fold(1, usize::saturating_add),
        Term::Array(array) => array.iter().map(term_size).fold(1, usize::saturating_add),
        Term::Map(map) => map
            .values()
            .map(|v| term_size(v).saturating_add(1))
            .fold(1, usize::saturating_add),
        _ => 1,
    }
}

/// The size of one expression operation, or `None` for an operation a later block may not use: a closure that
/// runs once for each element of a collection (`.all()`, `.any()`), or `.matches()`, which compiles its regex
/// every time it is evaluated. `&&`, `||` and `.try_or()` are closures without parameters, which run at most once.
fn op_size(op: &Op) -> Option<usize> {
    match op {
        Op::Value(term) => Some(term_size(term)),
        Op::Unary(_) => Some(1),
        Op::Binary(Binary::All | Binary::Any | Binary::Regex) => None,
        Op::Binary(_) => Some(1),
        Op::Closure(params, _) if !params.is_empty() => None,
        Op::Closure(_, ops) => ops
            .iter()
            .try_fold(1, |n: usize, op| Some(n.saturating_add(op_size(op)?))),
    }
}

fn bounded_query(query: &Rule) -> Result<(), TokenError> {
    if query.body.len() > MAX_QUERY_PREDICATES {
        return Err(TokenError::Rejected);
    }
    let terms = query
        .body
        .iter()
        .flat_map(|p| &p.terms)
        .map(term_size)
        .fold(0, usize::saturating_add);
    let size = query
        .expressions
        .iter()
        .flat_map(|e| &e.ops)
        .try_fold(terms, |n, op| Some(n.saturating_add(op_size(op)?)))
        .ok_or(TokenError::Rejected)?;
    if size > MAX_QUERY_SIZE {
        return Err(TokenError::Rejected);
    }
    Ok(())
}

/// Refuses a token whose blocks after the authority block hold anything but small checks (see the module docs),
/// before any of it runs.
fn bounded_attenuation(biscuit: &Biscuit) -> Result<(), TokenError> {
    let mut checks: usize = 0;
    for index in 1..biscuit.block_count() {
        let block = block_code(biscuit, index).ok_or(TokenError::Rejected)?;
        if !block.facts.is_empty() || !block.rules.is_empty() {
            return Err(TokenError::Rejected);
        }
        checks = checks.saturating_add(block.checks.len());
        if checks > MAX_ATTENUATION_CHECKS {
            return Err(TokenError::Rejected);
        }
        for check in &block.checks {
            if check.queries.len() > MAX_CHECK_ALTERNATIVES {
                return Err(TokenError::Rejected);
            }
            check.queries.iter().try_for_each(bounded_query)?;
        }
    }
    Ok(())
}

/// Verifies a base64 token against the issuer registry at time `now` (unix seconds), and reads its claims.
///
/// Every check inside the token, including any added by attenuation, is run with the time fact set to `now`.
/// Before any of them runs, an expired token is refused, and so is one whose later blocks hold anything but
/// small checks (see the module docs).
pub fn verify(
    token: &str,
    keys: &impl IssuerKeys,
    now: i64,
    max_ttl: i64,
) -> Result<Claims, TokenError> {
    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        return Err(TokenError::Malformed);
    }
    let biscuit = Biscuit::from_base64(token, Provider(keys)).map_err(|e| match e {
        error::Token::Format(error::Format::UnknownPublicKey) => TokenError::UnknownIssuer,
        error::Token::Format(error::Format::Signature(_)) => TokenError::Rejected,
        _ => TokenError::Malformed,
    })?;
    let issuer_key_id = biscuit.root_key_id().ok_or(TokenError::UnknownIssuer)?;
    expiry_first(&biscuit, now, max_ttl)?;
    bounded_attenuation(&biscuit)?;

    let mut authorizer = AuthorizerBuilder::new()
        .code(format!("time({});", rfc3339(now)?))
        .and_then(|b| b.policy("allow if true"))
        .map(|b| b.set_limits(run_limits()))
        .and_then(|b| b.build(&biscuit))
        .map_err(|_| TokenError::Rejected)?;
    // Runs the authority block's rules and checks, and every later block's checks, all within `run_limits`.
    authorizer.authorize().map_err(|_| TokenError::Rejected)?;

    let expires: Vec<(i64,)> = claim_query(&mut authorizer, "data($x) <- expires($x)")?;
    let expires = match expires.as_slice() {
        [(e,)] => *e,
        [] => return Err(TokenError::Missing("expires")),
        _ => return Err(TokenError::Invalid("expires")),
    };
    check_lifetime(expires, now, max_ttl)?;

    let request_id = at_most_one(strings(&mut authorizer, "request_id")?, "request_id")?
        .ok_or(TokenError::Missing("request_id"))?;
    let resource_fact = at_most_one(strings(&mut authorizer, "resource_fact")?, "resource_fact")?
        .map(|s| Uuid::parse_str(&s).map_err(|_| TokenError::Invalid("resource_fact")))
        .transpose()?;
    Ok(Claims {
        issuer_key_id,
        caller: at_most_one(strings(&mut authorizer, "caller")?, "caller")?,
        subject: at_most_one(strings(&mut authorizer, "subject")?, "subject")?,
        roles: strings(&mut authorizer, "role")?,
        purpose: at_most_one(strings(&mut authorizer, "purpose")?, "purpose")?,
        reason: at_most_one(strings(&mut authorizer, "reason")?, "reason")?,
        request_id,
        actions: strings(&mut authorizer, "action")?,
        resource_fact,
        resource_scope: at_most_one(
            strings(&mut authorizer, "resource_scope")?,
            "resource_scope",
        )?,
        resource_subject: at_most_one(
            strings(&mut authorizer, "resource_subject")?,
            "resource_subject",
        )?,
        grants: strings(&mut authorizer, "grant")?,
        approval: at_most_one(strings(&mut authorizer, "approval")?, "approval")?,
        expires,
    })
}

// --- Minting: for issuers' tests, the `pvlt` tool and examples. The vault itself never mints. -------------------

/// An issuer's key pair, as the 32-byte Ed25519 seed and the public key.
pub fn generate_issuer_key() -> ([u8; 32], [u8; 32]) {
    let pair = KeyPair::new();
    let seed = pair.private().to_bytes();
    let mut s = [0u8; 32];
    if seed.len() == 32 {
        s.copy_from_slice(&seed);
    }
    let public = pair.public().to_bytes();
    let mut p = [0u8; 32];
    if public.len() == 32 {
        p.copy_from_slice(&public);
    }
    (s, p)
}

/// The public key for a seed.
pub fn public_key_of(seed: &[u8; 32]) -> Result<[u8; 32], TokenError> {
    let pair = key_pair(seed)?;
    let bytes = pair.public().to_bytes();
    bytes
        .try_into()
        .map_err(|_| TokenError::Invalid("public key"))
}

fn key_pair(seed: &[u8; 32]) -> Result<KeyPair, TokenError> {
    PrivateKey::from_bytes(seed, Algorithm::Ed25519)
        .map(|k| KeyPair::from(&k))
        .map_err(|_| TokenError::Invalid("issuer key"))
}

fn add(b: BiscuitBuilder, name: &str, term: Term) -> Result<BiscuitBuilder, TokenError> {
    b.fact(Fact::new(name.to_owned(), vec![term]))
        .map_err(|_| TokenError::Invalid("claim"))
}

/// Mints a token. `claims.expires` and `claims.request_id` are required; `issuer_key_id` is the registry id
/// written as the token's root key id.
pub fn mint(seed: &[u8; 32], claims: &Claims) -> Result<String, TokenError> {
    let mut b = Biscuit::builder().root_key_id(claims.issuer_key_id);
    b = add(b, "expires", Term::Integer(claims.expires))?;
    b = add(b, "request_id", Term::Str(claims.request_id.clone()))?;
    let one = [
        ("caller", &claims.caller),
        ("subject", &claims.subject),
        ("purpose", &claims.purpose),
        ("reason", &claims.reason),
        ("resource_scope", &claims.resource_scope),
        ("resource_subject", &claims.resource_subject),
        ("approval", &claims.approval),
    ];
    for (name, value) in one {
        if let Some(v) = value {
            b = add(b, name, Term::Str(v.clone()))?;
        }
    }
    if let Some(f) = claims.resource_fact {
        b = add(b, "resource_fact", Term::Str(f.to_string()))?;
    }
    for (name, values) in [
        ("role", &claims.roles),
        ("action", &claims.actions),
        ("grant", &claims.grants),
    ] {
        for v in values {
            b = add(b, name, Term::Str(v.clone()))?;
        }
    }
    b.build(&key_pair(seed)?)
        .and_then(|t| t.to_base64())
        .map_err(|_| TokenError::Invalid("token"))
}

/// Narrows a token so it stops being valid at `not_after` (unix seconds), as any holder can. For tests and
/// examples; the vault treats an attenuated token like any other.
pub fn attenuate_expiry(
    token: &str,
    keys: &impl IssuerKeys,
    not_after: i64,
) -> Result<String, TokenError> {
    let biscuit = Biscuit::from_base64(token, Provider(keys)).map_err(|_| TokenError::Malformed)?;
    let block = BlockBuilder::new()
        .code(format!("check if time($t), $t < {};", rfc3339(not_after)?))
        .map_err(|_| TokenError::Invalid("check"))?;
    biscuit
        .append(block)
        .and_then(|t| t.to_base64())
        .map_err(|_| TokenError::Invalid("token"))
}

/// Adds a block of any Datalog, such as one that **claims** a role, as any holder can. The vault refuses a token
/// whose added block holds a fact or a rule, or a check past the attenuation limits; this exists so tests can
/// prove that.
pub fn attenuate_with_fact(
    token: &str,
    keys: &impl IssuerKeys,
    fact: &str,
) -> Result<String, TokenError> {
    let biscuit = Biscuit::from_base64(token, Provider(keys)).map_err(|_| TokenError::Malformed)?;
    let block = BlockBuilder::new()
        .code(fact)
        .map_err(|_| TokenError::Invalid("fact"))?;
    biscuit
        .append(block)
        .and_then(|t| t.to_base64())
        .map_err(|_| TokenError::Invalid("token"))
}
