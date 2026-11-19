//! Policy: what a role may do (REQUIREMENTS 3.7).
//!
//! The vault does not trust a claim because it is signed. A token says "I am acting as `verifier`"; whether that
//! is allowed depends on two things this module checks together: the issuer must be registered to assert that
//! role (so a compromised service cannot invent a role the policy never gave it), and the policy must allow the
//! role to do this to this kind of fact, under the stated purpose, with the stated conditions met.
//!
//! **Deny is the default.** Nothing here ever allows because something is missing.
//!
//! Policy is data: JSON in a fixed shape, validated strictly (unknown fields are an error), canonicalised with
//! the same JSON canonical form as the ledger, and identified by its SHA-256 so an audit entry can name the
//! exact policy that decided. There is no expression language: a condition is one of a short list.
//!
//! ```json
//! {
//!   "version": 1,
//!   "restricted_types": ["id_number"],
//!   "roles": {
//!     "verifier": {
//!       "allow": [{ "types": ["identity", "doc_key"], "actions": ["read"] }],
//!       "require": { "purposes": ["kyc-review"], "reason": true },
//!       "limits": { "read_per_hour": 100 }
//!     },
//!     "data-subject": { "allow": [{ "types": ["*"], "actions": ["read"], "when": ["self"] }] },
//!     "fulfillment": { "allow": [{ "types": ["address"], "actions": ["read"], "when": ["grant:order_open"] }] }
//!   }
//! }
//! ```

use std::collections::BTreeMap;

use pvlt_format::PREFIX;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Longest role name, fact type, purpose or grant name.
pub const MAX_NAME: usize = 64;
/// Most roles in a policy.
pub const MAX_ROLES: usize = 256;
/// The name of the role the static `/api/v1` token runs as.
pub const COMPAT_ROLE: &str = "compat";

/// What a request is trying to do to a fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Create a fact.
    Create,
    /// Read a fact's value.
    Read,
    /// Shred a fact, a scope or a subject.
    Shred,
    /// Move a fact to another scope.
    Rebind,
}

impl Action {
    /// The name used in policy, tokens and logs.
    pub fn name(self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Read => "read",
            Action::Shred => "shred",
            Action::Rebind => "rebind",
        }
    }

    /// Reads a name back.
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "create" => Action::Create,
            "read" => Action::Read,
            "shred" => Action::Shred,
            "rebind" => Action::Rebind,
            _ => return None,
        })
    }
}

/// A condition an allow rule can attach. Every condition listed must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// The caller is the data subject: the token names the same caller and subject, and the fact is filed under
    /// that subject.
    SelfAccess,
    /// The token carries this grant (a capability granted elsewhere, such as `order_open`).
    Grant(String),
}

impl Condition {
    fn parse(s: &str) -> Result<Self, PolicyError> {
        if s == "self" {
            return Ok(Condition::SelfAccess);
        }
        match s.strip_prefix("grant:") {
            Some(name) if valid_name(name) => Ok(Condition::Grant(name.to_owned())),
            _ => Err(PolicyError(
                "a condition must be \"self\" or \"grant:<name>\"",
            )),
        }
    }

    fn text(&self) -> String {
        match self {
            Condition::SelfAccess => "self".to_owned(),
            Condition::Grant(g) => format!("grant:{g}"),
        }
    }
}

/// One allow rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The fact types it covers. `*` means all.
    pub types: Vec<String>,
    /// The actions it covers.
    pub actions: Vec<Action>,
    /// Conditions that must all hold.
    pub when: Vec<Condition>,
}

/// What a role requires of the request before any rule applies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Require {
    /// The purpose must be one of these. Empty means no requirement.
    pub purposes: Vec<String>,
    /// A reason must be given.
    pub reason: bool,
}

/// Rate limits for a role, per caller.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoleLimits {
    /// Reads per hour.
    pub read_per_hour: Option<u32>,
    /// Creates per hour.
    pub create_per_hour: Option<u32>,
    /// Shreds per hour.
    pub shred_per_hour: Option<u32>,
}

impl RoleLimits {
    /// The limit for an action, if there is one.
    pub fn for_action(&self, action: Action) -> Option<u32> {
        match action {
            Action::Read => self.read_per_hour,
            Action::Create => self.create_per_hour,
            Action::Shred => self.shred_per_hour,
            Action::Rebind => None,
        }
    }
}

/// One role.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Role {
    /// What it may do.
    pub allow: Vec<Rule>,
    /// What it must say.
    pub require: Require,
    /// How often.
    pub limits: RoleLimits,
}

/// A parsed, validated policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policy {
    /// Fact types whose reads need a dual-control approval.
    pub restricted_types: Vec<String>,
    /// The roles.
    pub roles: BTreeMap<String, Role>,
}

/// Why a policy was refused. The message is fixed text and never echoes the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyError(pub &'static str);

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid policy: {}", self.0)
    }
}

impl std::error::Error for PolicyError {}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'*'))
}

// --- The JSON shape ---------------------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyDoc {
    version: u8,
    #[serde(default)]
    restricted_types: Vec<String>,
    #[serde(default)]
    roles: BTreeMap<String, RoleDoc>,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct RoleDoc {
    #[serde(default)]
    allow: Vec<RuleDoc>,
    #[serde(default)]
    require: RequireDoc,
    #[serde(default)]
    limits: LimitsDoc,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuleDoc {
    types: Vec<String>,
    actions: Vec<String>,
    #[serde(default)]
    when: Vec<String>,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct RequireDoc {
    #[serde(default)]
    purposes: Vec<String>,
    #[serde(default)]
    reason: bool,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct LimitsDoc {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    read_per_hour: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    create_per_hour: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shred_per_hour: Option<u32>,
}

impl Policy {
    /// Parses and validates a policy. Anything not understood is an error: a policy that silently ignores a
    /// misspelt field would allow or deny things its author did not mean.
    pub fn from_json(bytes: &[u8]) -> Result<Self, PolicyError> {
        let doc: PolicyDoc =
            serde_json::from_slice(bytes).map_err(|_| PolicyError("not a policy document"))?;
        if doc.version != 1 {
            return Err(PolicyError("unsupported version"));
        }
        if doc.roles.len() > MAX_ROLES {
            return Err(PolicyError("too many roles"));
        }
        if !doc
            .restricted_types
            .iter()
            .all(|t| valid_name(t) && t != "*")
        {
            return Err(PolicyError(
                "a restricted type must be a name, not a wildcard",
            ));
        }
        let mut roles = BTreeMap::new();
        for (name, role) in doc.roles {
            if !valid_name(&name) || name.contains('*') {
                return Err(PolicyError(
                    "a role name has characters that are not allowed",
                ));
            }
            let mut allow = Vec::with_capacity(role.allow.len());
            for rule in role.allow {
                if rule.types.is_empty() || !rule.types.iter().all(|t| valid_name(t)) {
                    return Err(PolicyError(
                        "a rule needs fact types, each a plain name or *",
                    ));
                }
                if rule.actions.is_empty() {
                    return Err(PolicyError("a rule needs actions"));
                }
                let actions = rule
                    .actions
                    .iter()
                    .map(|a| Action::parse(a).ok_or(PolicyError("unknown action")))
                    .collect::<Result<Vec<_>, _>>()?;
                let when = rule
                    .when
                    .iter()
                    .map(|c| Condition::parse(c))
                    .collect::<Result<Vec<_>, _>>()?;
                allow.push(Rule {
                    types: rule.types,
                    actions,
                    when,
                });
            }
            if !role.require.purposes.iter().all(|p| valid_name(p)) {
                return Err(PolicyError("a purpose has characters that are not allowed"));
            }
            roles.insert(
                name,
                Role {
                    allow,
                    require: Require {
                        purposes: role.require.purposes,
                        reason: role.require.reason,
                    },
                    limits: RoleLimits {
                        read_per_hour: role.limits.read_per_hour,
                        create_per_hour: role.limits.create_per_hour,
                        shred_per_hour: role.limits.shred_per_hour,
                    },
                },
            );
        }
        Ok(Self {
            restricted_types: doc.restricted_types,
            roles,
        })
    }

    /// The canonical JSON form: the same document with sorted keys and nothing else, so the same policy always
    /// has the same bytes and the same hash.
    pub fn canonical_json(&self) -> Result<Vec<u8>, PolicyError> {
        let doc = PolicyDoc {
            version: 1,
            restricted_types: sorted(&self.restricted_types),
            roles: self
                .roles
                .iter()
                .map(|(name, r)| {
                    (
                        name.clone(),
                        RoleDoc {
                            allow: r
                                .allow
                                .iter()
                                .map(|rule| RuleDoc {
                                    types: sorted(&rule.types),
                                    actions: {
                                        let mut a: Vec<String> = rule
                                            .actions
                                            .iter()
                                            .map(|a| a.name().to_owned())
                                            .collect();
                                        a.sort();
                                        a.dedup();
                                        a
                                    },
                                    when: {
                                        let mut w: Vec<String> =
                                            rule.when.iter().map(Condition::text).collect();
                                        w.sort();
                                        w.dedup();
                                        w
                                    },
                                })
                                .collect(),
                            require: RequireDoc {
                                purposes: sorted(&r.require.purposes),
                                reason: r.require.reason,
                            },
                            limits: LimitsDoc {
                                read_per_hour: r.limits.read_per_hour,
                                create_per_hour: r.limits.create_per_hour,
                                shred_per_hour: r.limits.shred_per_hour,
                            },
                        },
                    )
                })
                .collect(),
        };
        let value = serde_json::to_value(doc).map_err(|_| PolicyError("cannot encode"))?;
        pvlt_format::log::jcs(&value).map_err(|_| PolicyError("a number is out of range"))
    }

    /// `SHA-256(PREFIX ‖ "policy" ‖ 0x00 ‖ canonical JSON)`. Audit entries carry it.
    pub fn hash(&self) -> Result<[u8; 32], PolicyError> {
        let json = self.canonical_json()?;
        let mut h = Sha256::new();
        h.update(PREFIX);
        h.update(b"policy\0");
        h.update(&json);
        Ok(h.finalize().into())
    }
}

fn sorted(v: &[String]) -> Vec<String> {
    let mut v = v.to_vec();
    v.sort();
    v.dedup();
    v
}

// --- Deciding ---------------------------------------------------------------------------------------------

/// What the token says about who is acting, after the issuer's registration has been applied.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// Roles the token asserts.
    pub roles: &'a [String],
    /// The roles the issuer is registered to assert. A role outside this list is ignored.
    pub issuer_roles: &'a [String],
    /// The acting caller.
    pub caller: Option<&'a str>,
    /// The data subject.
    pub subject: Option<&'a str>,
    /// The stated purpose.
    pub purpose: Option<&'a str>,
    /// The stated reason.
    pub reason: Option<&'a str>,
    /// Grants the token carries.
    pub grants: &'a [String],
}

/// What is being attempted.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The action.
    pub action: Action,
    /// The fact type, if the action is on one fact. `None` for a shred of a whole scope or subject, where the
    /// type does not apply and only a rule that covers every type (`*`) can allow it.
    pub fact_type: Option<&'a str>,
    /// Whether the fact is filed under the subject the token names. Computed by the caller from the blind
    /// identifier, so the policy never sees a plaintext subject it could not have.
    pub subject_matches: bool,
}

/// Why a request was refused. A short stable code, for the audit log and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// No role the token asserts is one the issuer may assert and the policy knows.
    NoUsableRole,
    /// No rule of any usable role allows this action on this fact type.
    NotAllowed,
    /// A rule matched but its conditions did not hold.
    ConditionFailed,
    /// The role requires a purpose the token does not state, or states one that is not allowed.
    PurposeRequired,
    /// The role requires a reason and the token has none.
    ReasonRequired,
}

impl Denial {
    /// The stable code.
    pub fn code(self) -> &'static str {
        match self {
            Denial::NoUsableRole => "no_usable_role",
            Denial::NotAllowed => "not_allowed",
            Denial::ConditionFailed => "condition_failed",
            Denial::PurposeRequired => "purpose",
            Denial::ReasonRequired => "reason",
        }
    }
}

/// An allowed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    /// The role that allowed it.
    pub role: String,
    /// The role's limits.
    pub limits: RoleLimits,
    /// The action needs a dual-control approval before it proceeds.
    pub restricted: bool,
}

/// The outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Allowed, by this role.
    Allow(Allowed),
    /// Refused.
    Deny(Denial),
}

impl Policy {
    /// Decides a request. A role is usable only if the token asserts it, the issuer may assert it, and the
    /// policy defines it. The first usable role that allows the request wins; if none does, the denial is the
    /// one that got furthest (a missing reason is more useful to report than "not allowed").
    pub fn decide(&self, ctx: &Context<'_>, req: &Request<'_>) -> Decision {
        let usable: Vec<(&String, &Role)> = ctx
            .roles
            .iter()
            .filter(|r| ctx.issuer_roles.contains(r))
            .filter_map(|name| self.roles.get_key_value(name))
            .collect();
        if usable.is_empty() {
            return Decision::Deny(Denial::NoUsableRole);
        }
        let mut best = Denial::NotAllowed;
        for (name, role) in usable {
            match role_allows(role, ctx, req) {
                Ok(()) => {
                    let restricted = req.action == Action::Read
                        && req
                            .fact_type
                            .is_some_and(|t| self.restricted_types.iter().any(|r| r == t));
                    return Decision::Allow(Allowed {
                        role: name.clone(),
                        limits: role.limits,
                        restricted,
                    });
                }
                Err(d) => best = further(best, d),
            }
        }
        Decision::Deny(best)
    }

    /// Whether the policy defines the `compat` role, which is what narrows the static compat token. Without it
    /// that token may do anything.
    pub fn has_compat_role(&self) -> bool {
        self.roles.contains_key(COMPAT_ROLE)
    }

    /// Decides a request for the static compat token, which runs as the role named `compat`. If the policy has
    /// no such role the request is **allowed with no limits**, which is what the compat routes did before there
    /// was a policy: a deployment that wants the compat token narrowed defines the role.
    pub fn decide_compat(&self, req: &Request<'_>) -> Decision {
        match self.roles.get(COMPAT_ROLE) {
            None => Decision::Allow(Allowed {
                role: COMPAT_ROLE.to_owned(),
                limits: RoleLimits::default(),
                restricted: false,
            }),
            Some(role) => {
                let ctx = Context {
                    roles: &[],
                    issuer_roles: &[],
                    caller: None,
                    subject: None,
                    purpose: None,
                    reason: None,
                    grants: &[],
                };
                // The compat token states no purpose, reason or subject, so only a role without those
                // requirements and conditions can allow anything.
                match role_allows(role, &ctx, req) {
                    Ok(()) => Decision::Allow(Allowed {
                        role: COMPAT_ROLE.to_owned(),
                        limits: role.limits,
                        restricted: false,
                    }),
                    Err(d) => Decision::Deny(d),
                }
            }
        }
    }
}

fn rank(d: Denial) -> u8 {
    match d {
        Denial::NoUsableRole => 0,
        Denial::NotAllowed => 1,
        Denial::ConditionFailed => 2,
        Denial::PurposeRequired => 3,
        Denial::ReasonRequired => 4,
    }
}

fn further(a: Denial, b: Denial) -> Denial {
    if rank(b) > rank(a) { b } else { a }
}

fn role_allows(role: &Role, ctx: &Context<'_>, req: &Request<'_>) -> Result<(), Denial> {
    let mut result = Err(Denial::NotAllowed);
    for rule in &role.allow {
        if !rule.actions.contains(&req.action) {
            continue;
        }
        let covers_type = rule
            .types
            .iter()
            .any(|t| t == "*" || req.fact_type.is_some_and(|ft| ft == t));
        if !covers_type {
            continue;
        }
        let conditions_hold = rule.when.iter().all(|c| match c {
            Condition::SelfAccess => {
                ctx.caller.is_some() && ctx.caller == ctx.subject && req.subject_matches
            }
            Condition::Grant(g) => ctx.grants.iter().any(|x| x == g),
        });
        if conditions_hold {
            result = Ok(());
            break;
        }
        result = Err(Denial::ConditionFailed);
    }
    result?;
    // The role's own requirements apply once a rule has matched.
    if !role.require.purposes.is_empty()
        && !ctx
            .purpose
            .is_some_and(|p| role.require.purposes.iter().any(|x| x == p))
    {
        return Err(Denial::PurposeRequired);
    }
    if role.require.reason && ctx.reason.is_none_or(str::is_empty) {
        return Err(Denial::ReasonRequired);
    }
    Ok(())
}
