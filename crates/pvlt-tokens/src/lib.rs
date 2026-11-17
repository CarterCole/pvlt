//! Request tokens (REQUIREMENTS 3.7): short-lived [Biscuit](https://www.biscuitsec.org) tokens that a trusted
//! service mints for one operation, carrying who is acting and in what capacity.
//!
//! This crate only answers "is this token genuine, unexpired and signed by a key I was given, and what does it
//! claim?". **It decides nothing about permission.** What a claim is allowed to mean is the policy's job
//! (`pvlt_core::policy`), which does not trust a claim just because it is signed.
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
//! Later blocks can only **narrow** a token (add `check if ...`); their facts are never read, so a holder cannot
//! add a role by attenuating. The issuer is identified by the token's root key id, which the registry maps to a
//! public key. A token with no key id, an unknown key id, a bad signature, no `expires`, or an `expires` further
//! than `max_ttl` away is refused.

use core::fmt;

use biscuit_auth::builder::{
    Algorithm, AuthorizerBuilder, BiscuitBuilder, BlockBuilder, Fact, Term,
};
use biscuit_auth::{Biscuit, KeyPair, PrivateKey, PublicKey, RootKeyProvider, error};
use uuid::Uuid;

/// The longest token text accepted, before any parsing.
pub const MAX_TOKEN_LEN: usize = 8 * 1024;
/// The longest a single claim string may be.
pub const MAX_CLAIM_LEN: usize = 256;
/// The most values a repeatable claim may have.
pub const MAX_REPEATS: usize = 32;

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

fn strings(
    authorizer: &mut biscuit_auth::Authorizer,
    name: &'static str,
) -> Result<Vec<String>, TokenError> {
    let rule = format!("data($x) <- {name}($x)");
    let found: Vec<(String,)> = authorizer
        .query(rule.as_str())
        .map_err(|_| TokenError::Rejected)?;
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

/// Verifies a base64 token against the issuer registry at time `now` (unix seconds), and reads its claims.
///
/// Every check inside the token, including any added by attenuation, is run with the time fact set to `now`.
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

    let mut authorizer = AuthorizerBuilder::new()
        .code(format!("time({});", rfc3339(now)?))
        .and_then(|b| b.policy("allow if true"))
        .and_then(|b| b.build(&biscuit))
        .map_err(|_| TokenError::Rejected)?;
    // Runs the authority block's and every later block's checks.
    authorizer.authorize().map_err(|_| TokenError::Rejected)?;

    let expires: Vec<(i64,)> = authorizer
        .query("data($x) <- expires($x)")
        .map_err(|_| TokenError::Rejected)?;
    let expires = match expires.as_slice() {
        [(e,)] => *e,
        [] => return Err(TokenError::Missing("expires")),
        _ => return Err(TokenError::Invalid("expires")),
    };
    if expires <= now {
        return Err(TokenError::Expired);
    }
    if expires - now > max_ttl {
        return Err(TokenError::LifetimeTooLong);
    }

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

/// Adds a block that **claims** a role. The vault never reads facts from added blocks, so this has no effect;
/// it exists so tests can prove that.
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
