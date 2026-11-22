use std::time::Duration;

use pvlt_core::keys::{
    WrappedDek, WrappedDomainKeys, WrappedRoot, WrappedSigningKey, WrappedSubjectKey,
};
use pvlt_core::seal::{SealConfig, SealMode};
use pvlt_core::store::{
    AdminChangeRecord, ApprovalRecord, AuditAppend, AuditFilter, AuditRecord, BlobInfo, Destroyed,
    DomainRecord, DueFact, FactBundle, FactId, FactKind, FactRecord, IssuerRecord, KeyStore,
    LedgerAppend, LedgerHead, LedgerRecord, NewAdminChange, NewApproval, NewFact, NewSubjectKey,
    PolicyRecord, ReplayEffect, ShredFact, ShredPlan, ShredSubject, State, StoreError, SubjectFact,
    SubjectKeyRecord,
};
use pvlt_format::Id;
use pvlt_format::wrap::SignPurpose;
use pvlt_format::wrap::WRAPPED_LEN;
use sqlx::error::ErrorKind;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::{Postgres, Row, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

/// A key store in PostgreSQL.
#[derive(Debug, Clone)]
pub struct PgStore {
    pool: PgPool,
}

// --- Conversions -----------------------------------------------------------------------------------------

fn backend(e: sqlx::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// The bytes a shredded key is overwritten with.
fn zeros() -> Vec<u8> {
    vec![0; WRAPPED_LEN]
}

fn big(v: u32) -> i64 {
    i64::from(v)
}

fn u32_from(v: i64, what: &'static str) -> Result<u32, StoreError> {
    u32::try_from(v).map_err(|_| StoreError::Corrupt(what))
}

fn fixed<const N: usize>(v: Vec<u8>, what: &'static str) -> Result<[u8; N], StoreError> {
    v.try_into().map_err(|_| StoreError::Corrupt(what))
}

fn state_from(s: &str) -> Result<State, StoreError> {
    match s {
        "active" => Ok(State::Active),
        "shredded" => Ok(State::Shredded),
        _ => Err(StoreError::Corrupt("unknown state")),
    }
}

fn get<'r, T>(row: &'r PgRow, column: &str) -> Result<T, StoreError>
where
    T: sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column).map_err(backend)
}

/// Maps a driver error from an insert into the typed errors the trait promises.
fn insert_error(
    e: sqlx::Error,
    unique: &[(&str, StoreError)],
    foreign_key: StoreError,
) -> StoreError {
    let sqlx::Error::Database(db) = &e else {
        return backend(e);
    };
    match db.kind() {
        ErrorKind::UniqueViolation => {
            let name = db.constraint();
            unique
                .iter()
                .find(|(constraint, _)| Some(*constraint) == name)
                .map_or_else(
                    || StoreError::Backend(db.to_string()),
                    |(_, err)| err.clone(),
                )
        }
        ErrorKind::ForeignKeyViolation => foreign_key,
        ErrorKind::CheckViolation | ErrorKind::NotNullViolation => {
            StoreError::Conflict("record violates a constraint")
        }
        _ => StoreError::Backend(db.to_string()),
    }
}

// --- Row mapping -----------------------------------------------------------------------------------------

/// A domain from columns named `{p}state`, `{p}kek_version`, … with `p` as a prefix.
fn domain_from(row: &PgRow, domain_id: &Id, p: &str) -> Result<DomainRecord, StoreError> {
    let c = |name: &str| format!("{p}{name}");
    Ok(DomainRecord {
        domain_id: *domain_id,
        keys: WrappedDomainKeys {
            kek_version: u32_from(get(row, &c("kek_version"))?, "kek version")?,
            kek: get(row, &c("wrapped_kek"))?,
            bik_version: u32_from(get(row, &c("bik_version"))?, "bik version")?,
            bik: get(row, &c("wrapped_bik"))?,
            bix_version: u32_from(get(row, &c("bix_version"))?, "bix version")?,
            bix: get(row, &c("wrapped_bix"))?,
        },
        state: state_from(&get::<String>(row, &c("state"))?)?,
        created_at: get(row, &c("created_at"))?,
    })
}

fn subject_key_from(
    row: &PgRow,
    domain_id: &Id,
    subject_hmac: &[u8; 32],
    p: &str,
) -> Result<SubjectKeyRecord, StoreError> {
    let c = |name: &str| format!("{p}{name}");
    Ok(SubjectKeyRecord {
        domain_id: *domain_id,
        subject_hmac: *subject_hmac,
        bik_version: u32_from(get(row, &c("bik_version"))?, "bik version")?,
        key: WrappedSubjectKey {
            version: u32_from(get(row, &c("version"))?, "subject key version")?,
            kek_version: u32_from(get(row, &c("kek_version"))?, "kek version")?,
            wrapped: get(row, &c("wrapped_key"))?,
        },
        state: state_from(&get::<String>(row, &c("state"))?)?,
    })
}

fn fact_from(row: &PgRow, domain_id: &Id, fact_id: &FactId) -> Result<FactRecord, StoreError> {
    let subject_key_version = u32_from(get(row, "f_subject_key_version")?, "subject key version")?;
    Ok(FactRecord {
        fact: NewFact {
            domain_id: *domain_id,
            fact_id: *fact_id,
            subject_hmac: fixed(get(row, "f_subject_hmac")?, "subject hash length")?,
            bik_version: u32_from(get(row, "f_bik_version")?, "bik version")?,
            scope_hmac: fixed(get(row, "f_scope_hmac")?, "scope hash length")?,
            fact_type: get(row, "f_fact_type")?,
            object_id: fixed(get(row, "f_object_id")?, "object id length")?,
            size_class: u32::try_from(get::<i32>(row, "f_size_class")?)
                .map_err(|_| StoreError::Corrupt("size class"))?,
            dek: WrappedDek {
                subject_key_version,
                generation: u32_from(get(row, "f_dek_generation")?, "dek generation")?,
                wrapped: get(row, "f_wrapped_dek")?,
            },
            expires_at: get(row, "f_expires_at")?,
            legal_hold: get(row, "f_legal_hold")?,
        },
        state: state_from(&get::<String>(row, "f_state")?)?,
        created_at: get(row, "f_created_at")?,
        shredded_at: get(row, "f_shredded_at")?,
        kind: match get::<String>(row, "f_kind")?.as_str() {
            "fact" => FactKind::Fact,
            "blob" => FactKind::Blob,
            _ => return Err(StoreError::Corrupt("unknown fact kind")),
        },
        blob: match get::<Option<i32>>(row, "f_chunk_size")? {
            None => None,
            Some(cs) => Some(BlobInfo {
                chunk_size: u32::try_from(cs).map_err(|_| StoreError::Corrupt("chunk size"))?,
                len: u64::try_from(
                    get::<Option<i64>>(row, "f_blob_len")?
                        .ok_or(StoreError::Corrupt("blob length"))?,
                )
                .map_err(|_| StoreError::Corrupt("blob length"))?,
                ready: get(row, "f_ready")?,
                final_expires_at: get(row, "f_blob_expires_at")?,
            }),
        },
    })
}

fn seal_config_from(row: &PgRow) -> Result<SealConfig, StoreError> {
    let mode = match get::<String>(row, "mode")?.as_str() {
        "shamir" => SealMode::Shamir {
            threshold: u8::try_from(get::<i16>(row, "shamir_threshold")?)
                .map_err(|_| StoreError::Corrupt("threshold"))?,
            shares: u8::try_from(get::<i16>(row, "shamir_shares")?)
                .map_err(|_| StoreError::Corrupt("share count"))?,
        },
        #[cfg(feature = "dev-insecure")]
        "passphrase" => SealMode::Passphrase(pvlt_core::seal::PassphraseParams {
            m_kib: u32_from(get(row, "pass_m_kib")?, "argon2 memory")?,
            t_cost: u32_from(get(row, "pass_t_cost")?, "argon2 passes")?,
            p_cost: u32_from(get(row, "pass_p_cost")?, "argon2 lanes")?,
            salt: fixed(get(row, "pass_salt")?, "argon2 salt length")?,
        }),
        #[cfg(not(feature = "dev-insecure"))]
        "passphrase" => {
            return Err(StoreError::Corrupt(
                "this vault is sealed with a passphrase, which this build does not support",
            ));
        }
        _ => return Err(StoreError::Corrupt("unknown seal mode")),
    };
    Ok(SealConfig {
        root: WrappedRoot {
            id: fixed(get(row, "root_key_id")?, "root key id length")?,
            version: u32_from(get(row, "root_key_version")?, "root key version")?,
            wrapped: get(row, "wrapped_root")?,
        },
        mode,
        share_checks: share_checks_from_bytes(get(row, "shamir_share_checks")?)?,
    })
}

// --- Ledger helpers --------------------------------------------------------------------------------------

fn purpose_name(p: SignPurpose) -> &'static str {
    match p {
        SignPurpose::Ledger => "ledger",
        SignPurpose::Checkpoint => "checkpoint",
    }
}

fn seq_from(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt("ledger seq"))
}

fn record_from(row: &PgRow) -> Result<LedgerRecord, StoreError> {
    Ok(LedgerRecord {
        seq: seq_from(get(row, "seq")?)?,
        hash: fixed(get(row, "entry_hash")?, "ledger hash length")?,
        line: get(row, "line")?,
        published: get(row, "published")?,
    })
}

fn same_set<T: Ord + Clone>(a: &[T], b: &[T]) -> bool {
    let (mut a, mut b) = (a.to_vec(), b.to_vec());
    a.sort();
    a.dedup();
    b.sort();
    b.dedup();
    a == b
}

/// Appends a ledger row, first thing in the transaction, so concurrent shreds of one domain take turns on the
/// primary key. The head the caller saw must still be the head.
async fn append_ledger(
    tx: &mut Transaction<'_, Postgres>,
    domain_id: &Id,
    a: &LedgerAppend,
    published: bool,
) -> Result<(), StoreError> {
    let head = sqlx::query(
        "SELECT seq, entry_hash FROM ledger WHERE domain_id = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(domain_id.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(backend)?;
    let (want_seq, want_prev) = match &head {
        Some(row) => (
            seq_from(get(row, "seq")?)? + 1,
            fixed::<32>(get(row, "entry_hash")?, "ledger hash length")?,
        ),
        None => (0, [0u8; 32]),
    };
    if a.seq != want_seq || a.prev != want_prev {
        return Err(StoreError::Conflict("ledger moved"));
    }
    sqlx::query(
        "INSERT INTO ledger (domain_id, seq, prev_hash, entry_hash, line, published) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(domain_id.as_slice())
    .bind(i64::try_from(a.seq).map_err(|_| StoreError::Conflict("ledger seq out of range"))?)
    .bind(a.prev.as_slice())
    .bind(a.hash.as_slice())
    .bind(a.line.as_slice())
    .bind(published)
    .execute(&mut **tx)
    .await
    .map_err(|e| match &e {
        // Another shred took this sequence number first.
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            StoreError::Conflict("ledger moved")
        }
        _ => backend(e),
    })?;
    Ok(())
}

async fn zero_facts(
    tx: &mut Transaction<'_, Postgres>,
    domain_id: &Id,
    fact_ids: &[FactId],
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE facts SET wrapped_dek = $3, state = 'shredded', shredded_at = now() \
         WHERE domain_id = $1 AND fact_id = ANY($2) AND state = 'active'",
    )
    .bind(domain_id.as_slice())
    .bind(fact_ids)
    .bind(zeros())
    .execute(&mut **tx)
    .await
    .map_err(backend)?;
    Ok(())
}

/// Marks every active fact filed under a subject as shredded, with its wrapped key zeroed. Its subject key is
/// already destroyed, so it was unreadable; this makes the row say so.
async fn zero_subject_facts(
    tx: &mut Transaction<'_, Postgres>,
    domain_id: &Id,
    subject_hmac: &[u8; 32],
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE facts SET wrapped_dek = $3, state = 'shredded', shredded_at = now() \
         WHERE domain_id = $1 AND subject_hmac = $2 AND state = 'active'",
    )
    .bind(domain_id.as_slice())
    .bind(subject_hmac.as_slice())
    .bind(zeros())
    .execute(&mut **tx)
    .await
    .map_err(backend)?;
    Ok(())
}

/// Destroys everything in a domain. The caller has locked the domain row.
async fn shred_domain_rows(
    tx: &mut Transaction<'_, Postgres>,
    domain_id: &Id,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE facts SET wrapped_dek = $2, state = 'shredded', shredded_at = now() \
         WHERE domain_id = $1 AND state = 'active'",
    )
    .bind(domain_id.as_slice())
    .bind(zeros())
    .execute(&mut **tx)
    .await
    .map_err(backend)?;
    sqlx::query(
        "UPDATE subject_keys SET wrapped_key = $2, state = 'shredded', shredded_at = now() \
         WHERE domain_id = $1 AND state = 'active'",
    )
    .bind(domain_id.as_slice())
    .bind(zeros())
    .execute(&mut **tx)
    .await
    .map_err(backend)?;
    sqlx::query(
        "UPDATE domains SET wrapped_kek = $2, wrapped_bik = $2, wrapped_bix = $2, state = 'shredded', \
         shredded_at = now() WHERE domain_id = $1 AND state = 'active'",
    )
    .bind(domain_id.as_slice())
    .bind(zeros())
    .execute(&mut **tx)
    .await
    .map_err(backend)?;
    Ok(())
}

/// Inserts one fact inside a transaction. Holds the subject key row while inserting, so a subject shred cannot
/// slip in between the check and the insert: either it already happened (and this refuses) or it waits until the
/// transaction commits.
async fn insert_one(
    tx: &mut Transaction<'_, Postgres>,
    fact: &NewFact,
    blob: Option<(u32, u64, Option<OffsetDateTime>)>,
) -> Result<(), StoreError> {
    let key_state = sqlx::query(
        "SELECT state FROM subject_keys WHERE domain_id = $1 AND subject_hmac = $2 AND version = $3 FOR SHARE",
    )
    .bind(fact.domain_id.as_slice())
    .bind(fact.subject_hmac.as_slice())
    .bind(big(fact.dek.subject_key_version))
    .fetch_optional(&mut **tx)
    .await
    .map_err(backend)?
    .ok_or(StoreError::Conflict("subject key does not exist"))?;
    if state_from(&get::<String>(&key_state, "state")?)? == State::Shredded {
        return Err(StoreError::SubjectShredded);
    }
    sqlx::query(
        "INSERT INTO facts (domain_id, fact_id, subject_hmac, subject_key_version, bik_version, scope_hmac, \
         fact_type, object_id, size_class, dek_generation, wrapped_dek, expires_at, legal_hold, kind, chunk_size, \
         blob_len, ready, blob_expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)",
    )
    .bind(fact.domain_id.as_slice())
    .bind(fact.fact_id)
    .bind(fact.subject_hmac.as_slice())
    .bind(big(fact.dek.subject_key_version))
    .bind(big(fact.bik_version))
    .bind(fact.scope_hmac.as_slice())
    .bind(fact.fact_type.as_str())
    .bind(fact.object_id.as_slice())
    .bind(if blob.is_some() {
        0
    } else {
        i32::try_from(fact.size_class).map_err(|_| StoreError::Conflict("size class out of range"))?
    })
    .bind(big(fact.dek.generation))
    .bind(fact.dek.wrapped.as_slice())
    .bind(fact.expires_at)
    .bind(fact.legal_hold)
    .bind(if blob.is_some() { "blob" } else { "fact" })
    .bind(
        blob.map(|(cs, _, _)| i32::try_from(cs))
            .transpose()
            .map_err(|_| StoreError::Conflict("chunk size out of range"))?,
    )
    .bind(
        blob.map(|(_, len, _)| i64::try_from(len))
            .transpose()
            .map_err(|_| StoreError::Conflict("blob length out of range"))?,
    )
    .bind(blob.is_none())
    .bind(blob.and_then(|(_, _, at)| at))
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        insert_error(
            e,
            &[
                ("facts_pkey", StoreError::AlreadyExists),
                ("facts_object_id_key", StoreError::Conflict("object id already in use")),
            ],
            StoreError::Conflict("subject key does not exist"),
        )
    })?;
    Ok(())
}

fn audit_from(row: &PgRow) -> Result<AuditRecord, StoreError> {
    Ok(AuditRecord {
        seq: seq_from(get(row, "seq")?)?,
        prev: fixed(get(row, "prev_hash")?, "audit hash length")?,
        hash: fixed(get(row, "entry_hash")?, "audit hash length")?,
        line: get(row, "line")?,
        at: get(row, "at")?,
        kind: get(row, "kind")?,
        principal: get(row, "principal")?,
        fact_id: get(row, "fact_id")?,
        subject_hmac: get::<Option<Vec<u8>>>(row, "subject_hmac")?
            .map(|v| fixed(v, "subject hmac length"))
            .transpose()?,
    })
}

const AUDIT_COLUMNS: &str =
    "seq, prev_hash, entry_hash, line, at, kind, principal, fact_id, subject_hmac";

fn issuer_from(row: &PgRow) -> Result<IssuerRecord, StoreError> {
    Ok(IssuerRecord {
        key_id: u32::try_from(get::<i32>(row, "key_id")?)
            .map_err(|_| StoreError::Corrupt("issuer id"))?,
        name: get(row, "name")?,
        public_key: fixed(get(row, "public_key")?, "issuer key length")?,
        roles: get(row, "roles")?,
        enabled: get(row, "enabled")?,
    })
}

fn approval_from(row: &PgRow) -> Result<ApprovalRecord, StoreError> {
    Ok(ApprovalRecord {
        id: get(row, "id")?,
        domain_id: fixed(get(row, "domain_id")?, "domain id length")?,
        fact_id: get(row, "fact_id")?,
        requested_by: get(row, "requested_by")?,
        approved_by: get(row, "approved_by")?,
        break_glass: get(row, "break_glass")?,
        expires_at: get(row, "expires_at")?,
        used: get::<Option<OffsetDateTime>>(row, "used_at")?.is_some(),
        reader: get(row, "reader")?,
    })
}

const ADMIN_CHANGE_COLUMNS: &str = "id, kind, payload, requested_by, approved_by, expires_at";

fn admin_change_from(row: &PgRow) -> Result<AdminChangeRecord, StoreError> {
    Ok(AdminChangeRecord {
        id: get(row, "id")?,
        kind: get(row, "kind")?,
        payload: get(row, "payload")?,
        requested_by: get(row, "requested_by")?,
        approved_by: get(row, "approved_by")?,
        expires_at: get(row, "expires_at")?,
    })
}

/// Share checks as one column: `x ‖ hash` per share.
fn share_checks_to_bytes(checks: &[(u8, [u8; 32])]) -> Option<Vec<u8>> {
    if checks.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(checks.len() * 33);
    for (x, h) in checks {
        out.push(*x);
        out.extend_from_slice(h);
    }
    Some(out)
}

fn share_checks_from_bytes(bytes: Option<Vec<u8>>) -> Result<Vec<(u8, [u8; 32])>, StoreError> {
    let Some(bytes) = bytes else {
        return Ok(Vec::new());
    };
    let (records, rest) = bytes.as_chunks::<33>();
    if records.is_empty() || !rest.is_empty() {
        return Err(StoreError::Corrupt("share checks length"));
    }
    records
        .iter()
        .map(|c| {
            let (x, h) = c
                .split_first()
                .ok_or(StoreError::Corrupt("share checks length"))?;
            let h: [u8; 32] = h
                .try_into()
                .map_err(|_| StoreError::Corrupt("share checks length"))?;
            Ok((*x, h))
        })
        .collect()
}

// --- The store -------------------------------------------------------------------------------------------

impl PgStore {
    /// Connects a pool. `url` is a `postgres://` URL; add `?sslmode=verify-full` for a remote database.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(5))
            .connect(url)
            .await
            .map_err(backend)?;
        Ok(Self { pool })
    }

    /// Wraps an existing pool.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The underlying pool, for tests and tooling.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Applies any schema migrations that have not run. Safe to call on every start and from several
    /// instances at once: the migrator takes a lock.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

impl KeyStore for PgStore {
    async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(drop)
            .map_err(backend)
    }

    async fn seal_config(&self) -> Result<Option<SealConfig>, StoreError> {
        let row = sqlx::query(
            "SELECT root_key_id, root_key_version, wrapped_root, mode, shamir_threshold, shamir_shares, \
             pass_m_kib, pass_t_cost, pass_p_cost, pass_salt, shamir_share_checks FROM seal_config",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref().map(seal_config_from).transpose()
    }

    async fn init_seal_config(&self, config: &SealConfig) -> Result<(), StoreError> {
        #[allow(clippy::type_complexity)]
        let (mode, threshold, shares, m_kib, t_cost, p_cost, salt): (
            &str,
            Option<i16>,
            Option<i16>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<Vec<u8>>,
        ) = match &config.mode {
            SealMode::Shamir { threshold, shares } => (
                "shamir",
                Some(i16::from(*threshold)),
                Some(i16::from(*shares)),
                None,
                None,
                None,
                None,
            ),
            #[cfg(feature = "dev-insecure")]
            SealMode::Passphrase(p) => (
                "passphrase",
                None,
                None,
                Some(big(p.m_kib)),
                Some(big(p.t_cost)),
                Some(big(p.p_cost)),
                Some(p.salt.to_vec()),
            ),
            _ => {
                return Err(StoreError::Conflict(
                    "this seal mode cannot be stored by this build",
                ));
            }
        };
        let done = sqlx::query(
            "INSERT INTO seal_config (root_key_id, root_key_version, wrapped_root, mode, shamir_threshold, \
             shamir_shares, pass_m_kib, pass_t_cost, pass_p_cost, pass_salt, shamir_share_checks) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (singleton) DO NOTHING",
        )
        .bind(config.root.id.as_slice())
        .bind(big(config.root.version))
        .bind(config.root.wrapped.as_slice())
        .bind(mode)
        .bind(threshold)
        .bind(shares)
        .bind(m_kib)
        .bind(t_cost)
        .bind(p_cost)
        .bind(salt)
        .bind(share_checks_to_bytes(&config.share_checks))
        .execute(&self.pool)
        .await
        .map_err(|e| insert_error(e, &[], StoreError::Conflict("record violates a constraint")))?;
        if done.rows_affected() == 0 {
            Err(StoreError::AlreadyExists)
        } else {
            Ok(())
        }
    }

    async fn create_domain(
        &self,
        domain_id: &Id,
        keys: &WrappedDomainKeys,
    ) -> Result<(), StoreError> {
        let done = sqlx::query(
            "INSERT INTO domains (domain_id, kek_version, wrapped_kek, bik_version, wrapped_bik, bix_version, \
             wrapped_bix) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (domain_id) DO NOTHING",
        )
        .bind(domain_id.as_slice())
        .bind(big(keys.kek_version))
        .bind(keys.kek.as_slice())
        .bind(big(keys.bik_version))
        .bind(keys.bik.as_slice())
        .bind(big(keys.bix_version))
        .bind(keys.bix.as_slice())
        .execute(&self.pool)
        .await
        .map_err(|e| insert_error(e, &[], StoreError::Conflict("record violates a constraint")))?;
        if done.rows_affected() == 0 {
            Err(StoreError::AlreadyExists)
        } else {
            Ok(())
        }
    }

    async fn domain(&self, domain_id: &Id) -> Result<DomainRecord, StoreError> {
        let row = sqlx::query(
            "SELECT state, kek_version, wrapped_kek, bik_version, wrapped_bik, bix_version, wrapped_bix, created_at \
             FROM domains WHERE domain_id = $1",
        )
        .bind(domain_id.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?
        .ok_or(StoreError::NotFound)?;
        domain_from(&row, domain_id, "")
    }

    async fn subject_key(
        &self,
        domain_id: &Id,
        subject_hmac: &[u8; 32],
    ) -> Result<Option<SubjectKeyRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT version, bik_version, kek_version, wrapped_key, state FROM subject_keys \
             WHERE domain_id = $1 AND subject_hmac = $2 ORDER BY version DESC LIMIT 1",
        )
        .bind(domain_id.as_slice())
        .bind(subject_hmac.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref()
            .map(|r| subject_key_from(r, domain_id, subject_hmac, ""))
            .transpose()
    }

    async fn get_or_insert_subject_key(
        &self,
        new: &NewSubjectKey,
    ) -> Result<SubjectKeyRecord, StoreError> {
        sqlx::query(
            "INSERT INTO subject_keys (domain_id, subject_hmac, version, bik_version, kek_version, wrapped_key) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (domain_id, subject_hmac, version) DO NOTHING",
        )
        .bind(new.domain_id.as_slice())
        .bind(new.subject_hmac.as_slice())
        .bind(big(new.key.version))
        .bind(big(new.bik_version))
        .bind(big(new.key.kek_version))
        .bind(new.key.wrapped.as_slice())
        .execute(&self.pool)
        .await
        .map_err(|e| insert_error(e, &[], StoreError::Conflict("domain does not exist")))?;
        // Whoever won the insert, everyone reads the winner's row.
        self.subject_key(&new.domain_id, &new.subject_hmac)
            .await?
            .ok_or(StoreError::Corrupt("subject key vanished"))
    }

    async fn shred_subject_key(
        &self,
        domain_id: &Id,
        subject_hmac: &[u8; 32],
    ) -> Result<ShredSubject, StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        // Lock every version of the subject's key. A concurrent `insert_fact` holds FOR SHARE on the row it
        // uses, so this waits for it; a later insert then sees the shredded state.
        let rows = sqlx::query(
            "SELECT state FROM subject_keys WHERE domain_id = $1 AND subject_hmac = $2 FOR UPDATE",
        )
        .bind(domain_id.as_slice())
        .bind(subject_hmac.as_slice())
        .fetch_all(&mut *tx)
        .await
        .map_err(backend)?;
        if rows.is_empty() {
            return Ok(ShredSubject::NotFound);
        }
        let mut any_active = false;
        for row in &rows {
            any_active |= state_from(&get::<String>(row, "state")?)? == State::Active;
        }
        if !any_active {
            return Ok(ShredSubject::AlreadyShredded);
        }
        sqlx::query(
            "UPDATE subject_keys SET wrapped_key = $3, state = 'shredded', shredded_at = now() \
             WHERE domain_id = $1 AND subject_hmac = $2 AND state = 'active'",
        )
        .bind(domain_id.as_slice())
        .bind(subject_hmac.as_slice())
        .bind(zeros())
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(ShredSubject::Shredded)
    }

    async fn insert_fact(&self, fact: &NewFact) -> Result<(), StoreError> {
        self.insert_facts(core::slice::from_ref(fact)).await
    }

    async fn insert_facts(&self, facts: &[NewFact]) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        for fact in facts {
            insert_one(&mut tx, fact, None).await?;
        }
        tx.commit().await.map_err(backend)
    }

    async fn fact_for_read(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
    ) -> Result<FactBundle, StoreError> {
        // One statement, so one snapshot: the fact, its subject key and its domain agree with each other.
        let row = sqlx::query(
            "SELECT \
               f.subject_hmac AS f_subject_hmac, f.subject_key_version AS f_subject_key_version, \
               f.bik_version AS f_bik_version, f.scope_hmac AS f_scope_hmac, f.fact_type AS f_fact_type, \
               f.object_id AS f_object_id, f.size_class AS f_size_class, f.dek_generation AS f_dek_generation, \
               f.wrapped_dek AS f_wrapped_dek, f.state AS f_state, f.created_at AS f_created_at, \
               f.expires_at AS f_expires_at, f.legal_hold AS f_legal_hold, f.shredded_at AS f_shredded_at, \
               f.kind AS f_kind, f.chunk_size AS f_chunk_size, f.blob_len AS f_blob_len, f.ready AS f_ready, \
               f.blob_expires_at AS f_blob_expires_at, \
               s.version AS s_version, s.bik_version AS s_bik_version, s.kek_version AS s_kek_version, \
               s.wrapped_key AS s_wrapped_key, s.state AS s_state, \
               d.state AS d_state, d.kek_version AS d_kek_version, d.wrapped_kek AS d_wrapped_kek, \
               d.bik_version AS d_bik_version, d.wrapped_bik AS d_wrapped_bik, d.bix_version AS d_bix_version, \
               d.wrapped_bix AS d_wrapped_bix, d.created_at AS d_created_at \
             FROM facts f \
             JOIN subject_keys s ON s.domain_id = f.domain_id AND s.subject_hmac = f.subject_hmac \
                                AND s.version = f.subject_key_version \
             JOIN domains d ON d.domain_id = f.domain_id \
             WHERE f.domain_id = $1 AND f.fact_id = $2",
        )
        .bind(domain_id.as_slice())
        .bind(fact_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?
        .ok_or(StoreError::NotFound)?;

        let fact = fact_from(&row, domain_id, fact_id)?;
        let subject_key = subject_key_from(&row, domain_id, &fact.fact.subject_hmac, "s_")?;
        let domain = domain_from(&row, domain_id, "d_")?;
        Ok(FactBundle {
            fact,
            subject_key,
            domain,
        })
    }

    async fn shred_fact(&self, domain_id: &Id, fact_id: &FactId) -> Result<ShredFact, StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let Some(row) = sqlx::query(
            "SELECT state, legal_hold, object_id FROM facts WHERE domain_id = $1 AND fact_id = $2 FOR UPDATE",
        )
        .bind(domain_id.as_slice())
        .bind(fact_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?
        else {
            return Ok(ShredFact::NotFound);
        };
        if state_from(&get::<String>(&row, "state")?)? == State::Shredded {
            return Ok(ShredFact::AlreadyShredded);
        }
        if get::<bool>(&row, "legal_hold")? {
            return Err(StoreError::LegalHold);
        }
        let object_id: Id = fixed(get(&row, "object_id")?, "object id length")?;
        sqlx::query(
            "UPDATE facts SET wrapped_dek = $3, state = 'shredded', shredded_at = now() \
             WHERE domain_id = $1 AND fact_id = $2",
        )
        .bind(domain_id.as_slice())
        .bind(fact_id)
        .bind(zeros())
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(ShredFact::Shredded { object_id })
    }

    async fn live_object_ids(
        &self,
        domain_id: &Id,
        object_ids: &[Id],
    ) -> Result<Vec<Id>, StoreError> {
        let wanted: Vec<&[u8]> = object_ids.iter().map(|i| i.as_slice()).collect();
        let rows = sqlx::query(
            "SELECT f.object_id FROM facts f \
             JOIN subject_keys s ON s.domain_id = f.domain_id AND s.subject_hmac = f.subject_hmac \
                                AND s.version = f.subject_key_version \
             WHERE f.domain_id = $1 AND f.object_id = ANY($2) AND f.state = 'active' AND s.state = 'active'",
        )
        .bind(domain_id.as_slice())
        .bind(wanted)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(|row| fixed(get(row, "object_id")?, "object id length"))
            .collect()
    }

    async fn list_domains(&self) -> Result<Vec<Id>, StoreError> {
        sqlx::query("SELECT domain_id FROM domains ORDER BY domain_id")
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?
            .iter()
            .map(|r| fixed(get(r, "domain_id")?, "domain id length"))
            .collect()
    }

    async fn sign_key(
        &self,
        domain_id: &Id,
        purpose: SignPurpose,
    ) -> Result<Option<WrappedSigningKey>, StoreError> {
        let row = sqlx::query(
            "SELECT key_id, root_key_version, wrapped_seed, public_key FROM sign_keys \
             WHERE domain_id = $1 AND purpose = $2",
        )
        .bind(domain_id.as_slice())
        .bind(purpose_name(purpose))
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|r| {
            Ok(WrappedSigningKey {
                purpose,
                key_id: fixed(get(&r, "key_id")?, "signing key id length")?,
                root_key_version: u32_from(get(&r, "root_key_version")?, "root key version")?,
                wrapped: get(&r, "wrapped_seed")?,
                public_key: fixed(get(&r, "public_key")?, "signing public key length")?,
            })
        })
        .transpose()
    }

    async fn get_or_insert_sign_key(
        &self,
        domain_id: &Id,
        key: &WrappedSigningKey,
    ) -> Result<WrappedSigningKey, StoreError> {
        sqlx::query(
            "INSERT INTO sign_keys (domain_id, purpose, key_id, root_key_version, wrapped_seed, public_key) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (domain_id, purpose) DO NOTHING",
        )
        .bind(domain_id.as_slice())
        .bind(purpose_name(key.purpose))
        .bind(key.key_id.as_slice())
        .bind(big(key.root_key_version))
        .bind(key.wrapped.as_slice())
        .bind(key.public_key.as_slice())
        .execute(&self.pool)
        .await
        .map_err(|e| insert_error(e, &[], StoreError::Conflict("domain does not exist")))?;
        self.sign_key(domain_id, key.purpose)
            .await?
            .ok_or(StoreError::NotFound)
    }

    async fn ledger_head(&self, domain_id: &Id) -> Result<Option<LedgerHead>, StoreError> {
        let row = sqlx::query(
            "SELECT seq, entry_hash FROM ledger WHERE domain_id = $1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(domain_id.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|r| {
            Ok(LedgerHead {
                seq: seq_from(get(&r, "seq")?)?,
                hash: fixed(get(&r, "entry_hash")?, "ledger hash length")?,
            })
        })
        .transpose()
    }

    async fn ledger_records(
        &self,
        domain_id: &Id,
        from_seq: u64,
    ) -> Result<Vec<LedgerRecord>, StoreError> {
        sqlx::query(
            "SELECT seq, entry_hash, line, published FROM ledger \
             WHERE domain_id = $1 AND seq >= $2 ORDER BY seq",
        )
        .bind(domain_id.as_slice())
        .bind(i64::try_from(from_seq).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .iter()
        .map(record_from)
        .collect()
    }

    async fn ledger_unpublished(&self, domain_id: &Id) -> Result<Vec<LedgerRecord>, StoreError> {
        sqlx::query(
            "SELECT seq, entry_hash, line, published FROM ledger \
             WHERE domain_id = $1 AND NOT published ORDER BY seq",
        )
        .bind(domain_id.as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .iter()
        .map(record_from)
        .collect()
    }

    async fn ledger_mark_published(&self, domain_id: &Id, seq: u64) -> Result<(), StoreError> {
        let done =
            sqlx::query("UPDATE ledger SET published = true WHERE domain_id = $1 AND seq = $2")
                .bind(domain_id.as_slice())
                .bind(i64::try_from(seq).unwrap_or(i64::MAX))
                .execute(&self.pool)
                .await
                .map_err(backend)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn apply_shred(
        &self,
        domain_id: &Id,
        plan: &ShredPlan,
        append: &LedgerAppend,
    ) -> Result<Destroyed, StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let domain = sqlx::query("SELECT state FROM domains WHERE domain_id = $1 FOR UPDATE")
            .bind(domain_id.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?
            .ok_or(StoreError::NotFound)?;
        // The ledger row first: concurrent shreds of a domain take turns here, and one that lost finds out
        // before it has touched anything.
        append_ledger(&mut tx, domain_id, append, false).await?;

        let mut destroyed = Destroyed::default();
        match plan {
            ShredPlan::Facts { fact_ids } => {
                let rows = sqlx::query(
                    "SELECT fact_id, object_id, state, legal_hold FROM facts \
                     WHERE domain_id = $1 AND fact_id = ANY($2) FOR UPDATE",
                )
                .bind(domain_id.as_slice())
                .bind(fact_ids.as_slice())
                .fetch_all(&mut *tx)
                .await
                .map_err(backend)?;
                let mut found = Vec::with_capacity(rows.len());
                for row in &rows {
                    if state_from(&get::<String>(row, "state")?)? != State::Active {
                        return Err(StoreError::Conflict("plan names a shredded fact"));
                    }
                    if get::<bool>(row, "legal_hold")? {
                        return Err(StoreError::LegalHold);
                    }
                    found.push(get::<FactId>(row, "fact_id")?);
                    destroyed
                        .object_ids
                        .push(fixed(get(row, "object_id")?, "object id length")?);
                }
                if !same_set(&found, fact_ids) {
                    return Err(StoreError::Conflict("plan names an unknown fact"));
                }
                zero_facts(&mut tx, domain_id, fact_ids).await?;
            }
            ShredPlan::Scope {
                scope_hmac,
                fact_ids,
            } => {
                let rows = sqlx::query(
                    "SELECT fact_id, object_id, legal_hold FROM facts \
                     WHERE domain_id = $1 AND scope_hmac = $2 AND state = 'active' FOR UPDATE",
                )
                .bind(domain_id.as_slice())
                .bind(scope_hmac.as_slice())
                .fetch_all(&mut *tx)
                .await
                .map_err(backend)?;
                let mut found = Vec::with_capacity(rows.len());
                for row in &rows {
                    if get::<bool>(row, "legal_hold")? {
                        return Err(StoreError::LegalHold);
                    }
                    found.push(get::<FactId>(row, "fact_id")?);
                    destroyed
                        .object_ids
                        .push(fixed(get(row, "object_id")?, "object id length")?);
                }
                if !same_set(&found, fact_ids) {
                    return Err(StoreError::Conflict("scope changed since the plan"));
                }
                zero_facts(&mut tx, domain_id, fact_ids).await?;
            }
            ShredPlan::Subject {
                subject_hmac,
                versions,
            } => {
                let rows = sqlx::query(
                    "SELECT version FROM subject_keys \
                     WHERE domain_id = $1 AND subject_hmac = $2 AND state = 'active' FOR UPDATE",
                )
                .bind(domain_id.as_slice())
                .bind(subject_hmac.as_slice())
                .fetch_all(&mut *tx)
                .await
                .map_err(backend)?;
                let mut active = Vec::with_capacity(rows.len());
                for row in &rows {
                    active.push(u32_from(get(row, "version")?, "subject key version")?);
                }
                if active.is_empty() || !same_set(&active, versions) {
                    return Err(StoreError::Conflict("subject changed since the plan"));
                }
                let facts = sqlx::query(
                    "SELECT object_id, legal_hold FROM facts \
                     WHERE domain_id = $1 AND subject_hmac = $2 AND state = 'active'",
                )
                .bind(domain_id.as_slice())
                .bind(subject_hmac.as_slice())
                .fetch_all(&mut *tx)
                .await
                .map_err(backend)?;
                for row in &facts {
                    if get::<bool>(row, "legal_hold")? {
                        return Err(StoreError::LegalHold);
                    }
                    destroyed
                        .object_ids
                        .push(fixed(get(row, "object_id")?, "object id length")?);
                }
                sqlx::query(
                    "UPDATE subject_keys SET wrapped_key = $3, state = 'shredded', shredded_at = now() \
                     WHERE domain_id = $1 AND subject_hmac = $2 AND state = 'active'",
                )
                .bind(domain_id.as_slice())
                .bind(subject_hmac.as_slice())
                .bind(zeros())
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
                zero_subject_facts(&mut tx, domain_id, subject_hmac).await?;
            }
            ShredPlan::Domain => {
                if state_from(&get::<String>(&domain, "state")?)? == State::Shredded {
                    return Err(StoreError::Conflict("domain is already shredded"));
                }
                let facts = sqlx::query(
                    "SELECT object_id, legal_hold FROM facts WHERE domain_id = $1 AND state = 'active'",
                )
                .bind(domain_id.as_slice())
                .fetch_all(&mut *tx)
                .await
                .map_err(backend)?;
                for row in &facts {
                    if get::<bool>(row, "legal_hold")? {
                        return Err(StoreError::LegalHold);
                    }
                    destroyed
                        .object_ids
                        .push(fixed(get(row, "object_id")?, "object id length")?);
                }
                shred_domain_rows(&mut tx, domain_id).await?;
            }
        }
        tx.commit().await.map_err(backend)?;
        Ok(destroyed)
    }

    async fn replay_entry(
        &self,
        domain_id: &Id,
        effect: &ReplayEffect,
        append: &LedgerAppend,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let domain = sqlx::query("SELECT kek_version FROM domains WHERE domain_id = $1 FOR UPDATE")
            .bind(domain_id.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?
            .ok_or(StoreError::NotFound)?;
        let kek_version: i64 = get(&domain, "kek_version")?;
        append_ledger(&mut tx, domain_id, append, true).await?;
        match effect {
            ReplayEffect::Objects { object_ids } => {
                let wanted: Vec<&[u8]> = object_ids.iter().map(|i| i.as_slice()).collect();
                sqlx::query(
                    "UPDATE facts SET wrapped_dek = $3, state = 'shredded', shredded_at = now() \
                     WHERE domain_id = $1 AND object_id = ANY($2) AND state = 'active'",
                )
                .bind(domain_id.as_slice())
                .bind(wanted)
                .bind(zeros())
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            }
            ReplayEffect::Subject {
                subject_hmac,
                bik_version,
                versions,
            } => {
                for version in versions {
                    // A tombstone, if this key store never had the row, so a later write cannot reopen it.
                    sqlx::query(
                        "INSERT INTO subject_keys (domain_id, subject_hmac, version, bik_version, kek_version, \
                         wrapped_key, state, shredded_at) VALUES ($1, $2, $3, $4, $5, $6, 'shredded', now()) \
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(domain_id.as_slice())
                    .bind(subject_hmac.as_slice())
                    .bind(big(*version))
                    .bind(big(*bik_version))
                    .bind(kek_version)
                    .bind(zeros())
                    .execute(&mut *tx)
                    .await
                    .map_err(backend)?;
                    sqlx::query(
                        "UPDATE subject_keys SET wrapped_key = $4, state = 'shredded', shredded_at = now() \
                         WHERE domain_id = $1 AND subject_hmac = $2 AND version = $3 AND state = 'active'",
                    )
                    .bind(domain_id.as_slice())
                    .bind(subject_hmac.as_slice())
                    .bind(big(*version))
                    .bind(zeros())
                    .execute(&mut *tx)
                    .await
                    .map_err(backend)?;
                }
                zero_subject_facts(&mut tx, domain_id, subject_hmac).await?;
            }
            ReplayEffect::Domain => shred_domain_rows(&mut tx, domain_id).await?,
        }
        tx.commit().await.map_err(backend)
    }

    async fn active_facts_in_scope(
        &self,
        domain_id: &Id,
        scope_hmac: &[u8; 32],
    ) -> Result<Vec<(FactId, Id)>, StoreError> {
        sqlx::query(
            "SELECT fact_id, object_id FROM facts \
             WHERE domain_id = $1 AND scope_hmac = $2 AND state = 'active' ORDER BY fact_id",
        )
        .bind(domain_id.as_slice())
        .bind(scope_hmac.as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .iter()
        .map(|r| {
            Ok((
                get::<FactId>(r, "fact_id")?,
                fixed(get(r, "object_id")?, "object id length")?,
            ))
        })
        .collect()
    }

    async fn subject_facts(
        &self,
        domain_id: &Id,
        subject_hmac: &[u8; 32],
        limit: u32,
    ) -> Result<Vec<SubjectFact>, StoreError> {
        // One statement, so the fact, subject key and domain states come from one snapshot.
        sqlx::query(
            "SELECT f.fact_id, f.fact_type, f.kind, f.created_at, f.expires_at, f.legal_hold, f.shredded_at, \
               (f.state = 'shredded' OR s.state IS DISTINCT FROM 'active' OR d.state = 'shredded') AS gone \
             FROM facts f \
             JOIN domains d ON d.domain_id = f.domain_id \
             LEFT JOIN subject_keys s ON s.domain_id = f.domain_id AND s.subject_hmac = f.subject_hmac \
                                     AND s.version = f.subject_key_version \
             WHERE f.domain_id = $1 AND f.subject_hmac = $2 \
             ORDER BY f.created_at, f.fact_id LIMIT $3",
        )
        .bind(domain_id.as_slice())
        .bind(subject_hmac.as_slice())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .iter()
        .map(|r| {
            Ok(SubjectFact {
                fact_id: get(r, "fact_id")?,
                fact_type: get(r, "fact_type")?,
                kind: match get::<String>(r, "kind")?.as_str() {
                    "fact" => FactKind::Fact,
                    "blob" => FactKind::Blob,
                    _ => return Err(StoreError::Corrupt("unknown fact kind")),
                },
                state: if get::<bool>(r, "gone")? {
                    State::Shredded
                } else {
                    State::Active
                },
                created_at: get(r, "created_at")?,
                expires_at: get(r, "expires_at")?,
                legal_hold: get(r, "legal_hold")?,
                shredded_at: get(r, "shredded_at")?,
            })
        })
        .collect()
    }

    async fn subject_active_versions(
        &self,
        domain_id: &Id,
        subject_hmac: &[u8; 32],
    ) -> Result<Option<(u32, Vec<u32>)>, StoreError> {
        let rows = sqlx::query(
            "SELECT version, bik_version, state FROM subject_keys \
             WHERE domain_id = $1 AND subject_hmac = $2 ORDER BY version",
        )
        .bind(domain_id.as_slice())
        .bind(subject_hmac.as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        let Some(first) = rows.first() else {
            return Ok(None);
        };
        let bik = u32_from(get(first, "bik_version")?, "bik version")?;
        let mut active = Vec::new();
        for row in &rows {
            if state_from(&get::<String>(row, "state")?)? == State::Active {
                active.push(u32_from(get(row, "version")?, "subject key version")?);
            }
        }
        Ok(Some((bik, active)))
    }

    async fn due_facts(&self, domain_id: &Id, limit: u32) -> Result<Vec<DueFact>, StoreError> {
        sqlx::query(
            "SELECT fact_id, object_id FROM facts \
             WHERE domain_id = $1 AND state = 'active' AND NOT legal_hold \
               AND expires_at IS NOT NULL AND expires_at <= now() \
             ORDER BY expires_at, fact_id LIMIT $2",
        )
        .bind(domain_id.as_slice())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .iter()
        .map(|r| {
            Ok(DueFact {
                fact_id: get::<FactId>(r, "fact_id")?,
                object_id: fixed(get(r, "object_id")?, "object id length")?,
            })
        })
        .collect()
    }

    async fn set_legal_hold(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
        hold: bool,
    ) -> Result<(), StoreError> {
        let done = sqlx::query(
            "UPDATE facts SET legal_hold = $3 WHERE domain_id = $1 AND fact_id = $2 AND state = 'active'",
        )
        .bind(domain_id.as_slice())
        .bind(fact_id)
        .bind(hold)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if done.rows_affected() == 1 {
            return Ok(());
        }
        self.missing_or_shredded(domain_id, fact_id).await
    }

    async fn rebind_scope(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
        scope_hmac: &[u8; 32],
        bik_version: u32,
    ) -> Result<(), StoreError> {
        let done = sqlx::query(
            "UPDATE facts SET scope_hmac = $3, bik_version = $4 \
             WHERE domain_id = $1 AND fact_id = $2 AND state = 'active'",
        )
        .bind(domain_id.as_slice())
        .bind(fact_id)
        .bind(scope_hmac.as_slice())
        .bind(big(bik_version))
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if done.rows_affected() == 1 {
            return Ok(());
        }
        self.missing_or_shredded(domain_id, fact_id).await
    }
    async fn audit_head(&self, domain_id: &Id) -> Result<Option<LedgerHead>, StoreError> {
        let row = sqlx::query(
            "SELECT seq, entry_hash FROM audit WHERE domain_id = $1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(domain_id.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|r| {
            Ok(LedgerHead {
                seq: seq_from(get(&r, "seq")?)?,
                hash: fixed(get(&r, "entry_hash")?, "audit hash length")?,
            })
        })
        .transpose()
    }

    async fn append_audit(
        &self,
        domain_id: &Id,
        entries: &[AuditAppend],
    ) -> Result<(), StoreError> {
        let Some(first) = entries.first() else {
            return Ok(());
        };
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let head = sqlx::query(
            "SELECT seq, entry_hash FROM audit WHERE domain_id = $1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(domain_id.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?;
        let (want_seq, want_prev) = match &head {
            Some(r) => (
                seq_from(get(r, "seq")?)? + 1,
                fixed::<32>(get(r, "entry_hash")?, "audit hash length")?,
            ),
            None => (0, [0u8; 32]),
        };
        if first.seq != want_seq || first.prev != want_prev {
            return Err(StoreError::Conflict("audit log moved"));
        }
        let mut prev = want_prev;
        for (seq, e) in (want_seq..).zip(entries) {
            if e.seq != seq || e.prev != prev {
                return Err(StoreError::Conflict("audit batch is not a chain"));
            }
            sqlx::query(
                "INSERT INTO audit (domain_id, seq, prev_hash, entry_hash, line, at, kind, principal, fact_id, \
                 subject_hmac) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(domain_id.as_slice())
            .bind(i64::try_from(e.seq).map_err(|_| StoreError::Conflict("audit seq out of range"))?)
            .bind(e.prev.as_slice())
            .bind(e.hash.as_slice())
            .bind(e.line.as_slice())
            .bind(e.at)
            .bind(e.kind.as_str())
            .bind(e.principal.as_str())
            .bind(e.fact_id)
            .bind(e.subject_hmac.as_ref().map(|h| h.as_slice()))
            .execute(&mut *tx)
            .await
            .map_err(|err| match &err {
                // Another writer took this sequence number first.
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    StoreError::Conflict("audit log moved")
                }
                sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
                    StoreError::Conflict("domain does not exist")
                }
                _ => backend(err),
            })?;
            prev = e.hash;
        }
        tx.commit().await.map_err(backend)
    }

    async fn audit_records(
        &self,
        domain_id: &Id,
        from_seq: u64,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {AUDIT_COLUMNS} FROM audit WHERE domain_id = $1 AND seq >= $2 ORDER BY seq LIMIT $3"
        )))
        .bind(domain_id.as_slice())
        .bind(i64::try_from(from_seq).unwrap_or(i64::MAX))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .iter()
        .map(audit_from)
        .collect()
    }

    async fn audit_query(
        &self,
        domain_id: &Id,
        f: &AuditFilter,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        // Every condition is a fixed fragment; values are bound, never spliced in.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {AUDIT_COLUMNS} FROM audit WHERE domain_id = $1 \
               AND ($2::bigint IS NULL OR seq > $2) \
               AND ($3::bytea IS NULL OR subject_hmac = $3) \
               AND ($4::text IS NULL OR principal = $4) \
               AND ($5::uuid IS NULL OR fact_id = $5) \
               AND ($6::text IS NULL OR kind = $6) \
               AND ($7::timestamptz IS NULL OR at >= $7) \
               AND ($8::timestamptz IS NULL OR at < $8) \
             ORDER BY seq LIMIT $9"
        )))
        .bind(domain_id.as_slice())
        .bind(f.after_seq.map(|a| i64::try_from(a).unwrap_or(i64::MAX)))
        .bind(f.subject_hmac.as_ref().map(|h| h.as_slice()))
        .bind(f.principal.as_deref())
        .bind(f.fact_id)
        .bind(f.kind.as_deref())
        .bind(f.from)
        .bind(f.to)
        .bind(i64::from(f.limit))
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .iter()
        .map(audit_from)
        .collect()
    }

    async fn insert_blob(
        &self,
        fact: &NewFact,
        chunk_size: u32,
        len: u64,
        final_expires_at: Option<OffsetDateTime>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        insert_one(&mut tx, fact, Some((chunk_size, len, final_expires_at))).await?;
        tx.commit().await.map_err(backend)
    }

    async fn complete_blob(&self, domain_id: &Id, fact_id: &FactId) -> Result<(), StoreError> {
        let done = sqlx::query(
            "UPDATE facts SET ready = true, expires_at = blob_expires_at \
             WHERE domain_id = $1 AND fact_id = $2 AND kind = 'blob' AND state = 'active' AND NOT ready",
        )
        .bind(domain_id.as_slice())
        .bind(fact_id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if done.rows_affected() == 1 {
            return Ok(());
        }
        let exists = sqlx::query("SELECT 1 FROM facts WHERE domain_id = $1 AND fact_id = $2")
            .bind(domain_id.as_slice())
            .bind(fact_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
        Err(match exists {
            Some(_) => StoreError::Conflict("not a blob waiting for completion"),
            None => StoreError::NotFound,
        })
    }

    async fn issuers(&self) -> Result<Vec<IssuerRecord>, StoreError> {
        sqlx::query("SELECT key_id, name, public_key, roles, enabled FROM issuers ORDER BY key_id")
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?
            .iter()
            .map(issuer_from)
            .collect()
    }

    async fn create_issuer(
        &self,
        name: &str,
        public_key: &[u8; 32],
        roles: &[String],
    ) -> Result<IssuerRecord, StoreError> {
        let row = sqlx::query(
            "INSERT INTO issuers (name, public_key, roles) VALUES ($1, $2, $3) \
             RETURNING key_id, name, public_key, roles, enabled",
        )
        .bind(name)
        .bind(public_key.as_slice())
        .bind(roles)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => StoreError::AlreadyExists,
            sqlx::Error::Database(db) if db.is_check_violation() => {
                StoreError::Conflict("issuer record violates a constraint")
            }
            _ => backend(e),
        })?;
        issuer_from(&row)
    }

    async fn set_issuer_enabled(&self, key_id: u32, enabled: bool) -> Result<(), StoreError> {
        let done = sqlx::query("UPDATE issuers SET enabled = $2 WHERE key_id = $1")
            .bind(i32::try_from(key_id).map_err(|_| StoreError::NotFound)?)
            .bind(enabled)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn current_policy(&self) -> Result<Option<PolicyRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT version, doc, hash, created_by FROM policies ORDER BY version DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|r| {
            Ok(PolicyRecord {
                version: get(&r, "version")?,
                json: get(&r, "doc")?,
                hash: fixed(get(&r, "hash")?, "policy hash length")?,
                created_by: get(&r, "created_by")?,
            })
        })
        .transpose()
    }

    async fn put_policy(
        &self,
        json: &[u8],
        hash: &[u8; 32],
        created_by: &str,
    ) -> Result<PolicyRecord, StoreError> {
        let row = sqlx::query(
            "INSERT INTO policies (doc, hash, created_by) VALUES ($1, $2, $3) RETURNING version",
        )
        .bind(json)
        .bind(hash.as_slice())
        .bind(created_by)
        .fetch_one(&self.pool)
        .await
        .map_err(backend)?;
        Ok(PolicyRecord {
            version: get(&row, "version")?,
            json: json.to_vec(),
            hash: *hash,
            created_by: created_by.to_owned(),
        })
    }

    async fn create_approval(&self, new: &NewApproval) -> Result<ApprovalRecord, StoreError> {
        let row = sqlx::query(
            "INSERT INTO approvals (id, domain_id, fact_id, requested_by, approved_by, approved_at, \
             break_glass, expires_at, reader) \
             VALUES ($1, $2, $3, $4, CASE WHEN $5 THEN $4 END, CASE WHEN $5 THEN now() END, $5, $6, $7) \
             RETURNING id, domain_id, fact_id, requested_by, approved_by, break_glass, expires_at, used_at, reader",
        )
        .bind(new.id)
        .bind(new.domain_id.as_slice())
        .bind(new.fact_id)
        .bind(new.requested_by.as_str())
        .bind(new.break_glass)
        .bind(new.expires_at)
        .bind(new.reader.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            insert_error(
                e,
                &[("approvals_pkey", StoreError::AlreadyExists)],
                StoreError::Conflict("domain does not exist"),
            )
        })?;
        approval_from(&row)
    }

    async fn approve(
        &self,
        id: &Uuid,
        approver: &str,
        now: OffsetDateTime,
    ) -> Result<ApprovalRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let row = sqlx::query(
            "SELECT id, domain_id, fact_id, requested_by, approved_by, break_glass, expires_at, used_at, reader \
             FROM approvals WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?
        .ok_or(StoreError::NotFound)?;
        let rec = approval_from(&row)?;
        if rec.approved_by.is_some() {
            return Err(StoreError::Conflict("already approved"));
        }
        if rec.expires_at <= now {
            return Err(StoreError::Conflict("the request expired"));
        }
        if rec.requested_by == approver {
            return Err(StoreError::Conflict(
                "an approver must not be the requester",
            ));
        }
        sqlx::query("UPDATE approvals SET approved_by = $2, approved_at = now() WHERE id = $1")
            .bind(id)
            .bind(approver)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(ApprovalRecord {
            approved_by: Some(approver.to_owned()),
            ..rec
        })
    }

    async fn consume_approval(
        &self,
        domain_id: &Id,
        id: &Uuid,
        fact_id: &FactId,
        caller: &str,
        now: OffsetDateTime,
    ) -> Result<(), StoreError> {
        // One statement, so two uses at once cannot both succeed: only one UPDATE sees `used_at IS NULL`.
        let done = sqlx::query(
            "UPDATE approvals SET used_at = now() \
             WHERE id = $1 AND domain_id = $2 AND fact_id = $3 AND approved_by IS NOT NULL \
               AND used_at IS NULL AND expires_at > $4 AND reader = $5",
        )
        .bind(id)
        .bind(domain_id.as_slice())
        .bind(fact_id)
        .bind(now)
        .bind(caller)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::Conflict("approval is not valid"));
        }
        Ok(())
    }

    async fn create_admin_change(
        &self,
        new: &NewAdminChange,
    ) -> Result<AdminChangeRecord, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO admin_changes (id, kind, payload, requested_by, expires_at) \
             VALUES ($1, $2, $3, $4, $5) RETURNING {ADMIN_CHANGE_COLUMNS}"
        )))
        .bind(new.id)
        .bind(new.kind.as_str())
        .bind(new.payload.as_slice())
        .bind(new.requested_by.as_str())
        .bind(new.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            insert_error(
                e,
                &[("admin_changes_pkey", StoreError::AlreadyExists)],
                StoreError::Conflict("admin change violates a constraint"),
            )
        })?;
        admin_change_from(&row)
    }

    async fn admin_change(&self, id: &Uuid) -> Result<AdminChangeRecord, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {ADMIN_CHANGE_COLUMNS} FROM admin_changes WHERE id = $1"
        )))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?
        .ok_or(StoreError::NotFound)?;
        admin_change_from(&row)
    }

    async fn approve_admin_change(
        &self,
        id: &Uuid,
        approver: &str,
        now: OffsetDateTime,
    ) -> Result<AdminChangeRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {ADMIN_CHANGE_COLUMNS} FROM admin_changes WHERE id = $1 FOR UPDATE"
        )))
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?
        .ok_or(StoreError::NotFound)?;
        let rec = admin_change_from(&row)?;
        if rec.approved_by.is_some() {
            return Err(StoreError::Conflict("already approved"));
        }
        if rec.expires_at <= now {
            return Err(StoreError::Conflict("the request expired"));
        }
        if rec.requested_by == approver {
            return Err(StoreError::Conflict(
                "an approver must not be the requester",
            ));
        }
        sqlx::query("UPDATE admin_changes SET approved_by = $2, approved_at = now() WHERE id = $1")
            .bind(id)
            .bind(approver)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(AdminChangeRecord {
            approved_by: Some(approver.to_owned()),
            ..rec
        })
    }
}

/// The unseal key wrapped by a KMS: ciphertext, and which KMS key made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsSeal {
    /// The root key this unseal key opens.
    pub root_key_id: Id,
    /// The KMS provider, `aws-kms`.
    pub provider: String,
    /// The KMS key that wrapped it (an ARN or alias, as configured when it was enrolled).
    pub key_id: String,
    /// The KMS's ciphertext. Useless without decrypt permission on that key.
    pub wrapped: Vec<u8>,
}

impl PgStore {
    /// The stored auto-unseal record, if the vault was enrolled.
    pub async fn kms_seal(&self) -> Result<Option<KmsSeal>, StoreError> {
        let row = sqlx::query("SELECT root_key_id, provider, key_id, wrapped FROM seal_kms")
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
        row.map(|row| {
            Ok(KmsSeal {
                root_key_id: fixed(get::<Vec<u8>>(&row, "root_key_id")?, "kms seal root key id")?,
                provider: get(&row, "provider")?,
                key_id: get(&row, "key_id")?,
                wrapped: get(&row, "wrapped")?,
            })
        })
        .transpose()
    }

    /// Stores the auto-unseal record, replacing an earlier one (enrolling again with another KMS key).
    pub async fn set_kms_seal(&self, seal: &KmsSeal) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO seal_kms (root_key_id, provider, key_id, wrapped) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (singleton) DO UPDATE SET root_key_id = EXCLUDED.root_key_id, \
             provider = EXCLUDED.provider, key_id = EXCLUDED.key_id, wrapped = EXCLUDED.wrapped, \
             created_at = now()",
        )
        .bind(seal.root_key_id.as_slice())
        .bind(&seal.provider)
        .bind(&seal.key_id)
        .bind(&seal.wrapped)
        .execute(&self.pool)
        .await
        .map(drop)
        .map_err(|e| insert_error(e, &[], StoreError::Conflict("record violates a constraint")))
    }

    /// Removes the auto-unseal record. Returns whether there was one.
    pub async fn clear_kms_seal(&self) -> Result<bool, StoreError> {
        let done = sqlx::query("DELETE FROM seal_kms")
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(done.rows_affected() > 0)
    }
}

impl PgStore {
    /// Why an update of an active fact touched nothing: there is no such fact, or it is shredded.
    async fn missing_or_shredded(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
    ) -> Result<(), StoreError> {
        let exists = sqlx::query("SELECT 1 FROM facts WHERE domain_id = $1 AND fact_id = $2")
            .bind(domain_id.as_slice())
            .bind(fact_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
        Err(match exists {
            Some(_) => StoreError::Conflict("fact is shredded"),
            None => StoreError::NotFound,
        })
    }
}
