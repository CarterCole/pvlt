//! Export and import of the whole key store, for `pvlt backup` and `pvlt restore`.
//!
//! The key store holds only wrapped keys, ids, blind identifiers and the signed ledger, so an export contains no
//! plaintext. It is still sensitive (wrapped keys, and who accessed which fact), so the server encrypts it
//! before it is written anywhere. Rows travel as JSON as Postgres renders them, which keeps this code from
//! knowing the columns: a new migration needs no change here.

use pvlt_core::store::StoreError;
use serde_json::Value;
use sqlx::Row;

use crate::PgStore;

/// The tables in a backup, in the order they must be loaded (parents before children).
pub const BACKUP_TABLES: [&str; 10] = [
    "seal_config",
    "domains",
    "subject_keys",
    "facts",
    "sign_keys",
    "ledger",
    "audit",
    "issuers",
    "policies",
    "approvals",
];

/// Tables with an identity column, and the column. A restore writes the ids as they were and then moves the
/// sequence past them.
const IDENTITIES: [(&str, &str); 2] = [("issuers", "key_id"), ("policies", "version")];

/// One table's rows.
#[derive(Debug, Clone, PartialEq)]
pub struct TableDump {
    /// The table name, one of [`BACKUP_TABLES`].
    pub table: String,
    /// Its rows as JSON objects.
    pub rows: Vec<Value>,
}

fn backend(e: sqlx::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

impl PgStore {
    /// Reads every backed-up table inside one transaction, so the dump is a single consistent snapshot.
    pub async fn export_all(&self) -> Result<Vec<TableDump>, StoreError> {
        let mut tx = self.pool().begin().await.map_err(backend)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        let mut out = Vec::with_capacity(BACKUP_TABLES.len());
        for table in BACKUP_TABLES {
            // `table` is one of the constants above, never input.
            let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT row_to_json(t) AS r FROM {table} t ORDER BY row_to_json(t)::text"
            )))
            .fetch_all(&mut *tx)
            .await
            .map_err(backend)?
            .iter()
            .map(|r| r.try_get::<Value, _>("r").map_err(backend))
            .collect::<Result<Vec<_>, _>>()?;
            out.push(TableDump {
                table: table.to_owned(),
                rows,
            });
        }
        tx.commit().await.map_err(backend)?;
        Ok(out)
    }

    /// Loads a dump into an **empty** key store, in one transaction. Refuses if the key store already has a seal
    /// configuration or a domain: a restore never merges into live data.
    pub async fn import_all(&self, dump: &[TableDump]) -> Result<(), StoreError> {
        let names: Vec<&str> = dump.iter().map(|t| t.table.as_str()).collect();
        if names != BACKUP_TABLES {
            return Err(StoreError::Conflict(
                "the backup does not have the expected tables",
            ));
        }
        let mut tx = self.pool().begin().await.map_err(backend)?;
        for table in BACKUP_TABLES {
            let n: i64 =
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(backend)?;
            if n != 0 {
                return Err(StoreError::Conflict("the key store is not empty"));
            }
        }
        for t in dump {
            if t.rows.is_empty() {
                continue;
            }
            let table = t.table.as_str();
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "INSERT INTO {table} OVERRIDING SYSTEM VALUE \
                 SELECT * FROM json_populate_recordset(NULL::{table}, $1::json)"
            )))
            .bind(sqlx::types::Json(&t.rows))
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        }
        for (table, column) in IDENTITIES {
            // Both names come from the constant above.
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT setval(pg_get_serial_sequence('{table}', '{column}'), \
                 COALESCE((SELECT max({column}) FROM {table}), 0) + 1, false)"
            )))
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        }
        tx.commit().await.map_err(backend)
    }
}
