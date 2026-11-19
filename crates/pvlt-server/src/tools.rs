//! The operator tools behind `pvlt backup`, `pvlt restore` and `pvlt scrub-backup`.
//!
//! They are library functions so they can be tested against real databases. The command line in `main.rs` is a
//! thin wrapper.

use std::io::Write;
use std::path::Path;

use crate::pg::PgStore;
use pvlt_core::audit::Auditor;
use pvlt_core::engine::{Engine, ReconcileReport};
use pvlt_core::ledger;
use pvlt_core::objects::ObjectStore;
use pvlt_core::store::KeyStore;
use zeroize::Zeroizing;

use crate::backup::{self, BackupError, SigningKey, Trust};

fn err(m: impl Into<String>) -> BackupError {
    BackupError(m.into())
}

/// Writes a file readable only by its owner, and refuses to overwrite one that exists.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| err(format!("cannot create {}: {}", path.display(), e.kind())))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| err(format!("cannot write {}: {}", path.display(), e.kind())))
}

fn read_secret_file(path: &Path) -> Result<Zeroizing<String>, BackupError> {
    std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|e| err(format!("cannot read {}: {}", path.display(), e.kind())))
}

/// Exports the key store, signs it with `signer`, encrypts it to `recipients` and writes it to `out`. Returns how
/// many rows it holds.
pub async fn backup_to_file(
    store: &PgStore,
    out: &Path,
    recipients: &[String],
    signer: &SigningKey,
) -> Result<usize, BackupError> {
    let dump = store.export_all().await.map_err(|e| err(e.to_string()))?;
    let rows = dump.iter().map(|t| t.rows.len()).sum();
    let created = ledger::format_time(time::OffsetDateTime::now_utc());
    let plain = backup::encode(&created, &dump, signer)?;
    let cipher = backup::encrypt(&plain, recipients)?;
    write_new(out, &cipher)?;
    Ok(rows)
}

/// Loads a backup into the (empty) key store behind `engine`, then reconciles it with the bucket's ledger, so
/// everything shredded since the backup is shredded again **before** anything can read it.
pub async fn restore_from_file<O: ObjectStore, A: Auditor>(
    store: &PgStore,
    engine: &Engine<PgStore, O, A>,
    input: &Path,
    identity_file: &Path,
    trust: &Trust,
) -> Result<ReconcileReport, BackupError> {
    let dump = read_backup(input, identity_file, trust)?;
    store
        .import_all(&dump)
        .await
        .map_err(|e| err(e.to_string()))?;
    engine
        .reconcile()
        .await
        .map_err(|e| err(format!("restored, but the ledger check failed: {e}")))
}

/// Rewrites a backup so everything shredded since it was taken is already shredded in it, which lets an old
/// backup be kept or handed on without the keys of people who have since been erased. It loads the backup into
/// a scratch key store (`scratch`, which must be empty), replays the bucket's ledger there, and exports that.
///
/// It takes both ends of a backup: what to trust in the one it reads, and what to sign the one it writes with.
#[allow(clippy::too_many_arguments)]
pub async fn scrub_backup<O: ObjectStore, A: Auditor>(
    scratch: &PgStore,
    engine: &Engine<PgStore, O, A>,
    input: &Path,
    identity_file: &Path,
    trust: &Trust,
    out: &Path,
    recipients: &[String],
    signer: &SigningKey,
) -> Result<ReconcileReport, BackupError> {
    let report = restore_from_file(scratch, engine, input, identity_file, trust).await?;
    backup_to_file(scratch, out, recipients, signer).await?;
    Ok(report)
}

fn read_backup(
    input: &Path,
    identity_file: &Path,
    trust: &Trust,
) -> Result<Vec<crate::pg::TableDump>, BackupError> {
    let cipher = std::fs::read(input)
        .map_err(|e| err(format!("cannot read {}: {}", input.display(), e.kind())))?;
    let identity = read_secret_file(identity_file)?;
    let plain = backup::decrypt(&cipher, &identity)?;
    backup::decode(&plain, trust)
}

/// Whether the engine's store is what the tools were given. A guard against pointing `restore` at a live
/// database: it refuses if the key store already has a seal configuration.
pub async fn must_be_empty(store: &PgStore) -> Result<(), BackupError> {
    if store
        .seal_config()
        .await
        .map_err(|e| err(e.to_string()))?
        .is_some()
    {
        return Err(err(
            "this key store is already initialised; restore only into an empty one",
        ));
    }
    Ok(())
}
