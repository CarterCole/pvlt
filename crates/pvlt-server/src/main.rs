//! The `pvlt` command.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use pvlt_core::audit::{AuditEvent, Auditor};
use pvlt_core::engine::{Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::objects::SplitStore;
use pvlt_core::seal::init_shamir;
use pvlt_core::store::{KeyStore, StoreError};
use pvlt_mem::{Arena, LockPolicy, harden_process};
use pvlt_server::app::{Admin, App, Token};
use pvlt_server::bucket::Bucket;
use pvlt_server::config::{Config, Env, Storage};
use pvlt_server::pg::PgStore;
use pvlt_server::tls::{Transport, load_tls, serve, stop_signal};
use pvlt_server::{INSECURE_BUILD, admin, backup, routes, tools};
use tokio::net::TcpListener;
use tokio::sync::watch;

/// Writes one structured log line per engine operation (PLAN.md 3.4). Not a durable audit log: that is M4.
struct LogAuditor;

impl Auditor for LogAuditor {
    fn record(&self, e: &AuditEvent<'_>) {
        tracing::info!(
            target: "audit",
            principal = e.principal,
            action = e.action.name(),
            fact_id = e.fact_id.map(|i| i.to_string()),
            outcome = e.outcome,
        );
    }
}

type Objects = SplitStore<Bucket, Bucket>;
type Server = Engine<PgStore, Objects, LogAuditor>;

const USAGE: &str = "usage:
  pvlt init [--threshold N] [--shares N]    make the root key and print the unseal shares (once)
  pvlt serve                                start the server, sealed; unseal it with POST /v2/sys/unseal
  pvlt backup --out FILE --recipient R... --signing-key-file FILE
                                            write a signed, encrypted backup of the key store
  pvlt restore --in FILE --identity FILE (--verify-key HEX | --allow-unsigned)
                                            load a backup into an empty key store, then replay the ledger
  pvlt scrub-backup --in FILE --identity FILE (--verify-key HEX | --allow-unsigned)
                    --out FILE --recipient R... --signing-key-file FILE
                                            rewrite a backup so later shreds are already applied
                                            (needs PVLT_SCRATCH_DATABASE_URL(_FILE), an empty database)
  pvlt backup-keygen                        make an age key pair for backups
  pvlt backup-signing-keygen                make the Ed25519 key a backup job signs backups with
  pvlt issuer-keygen                        make an Ed25519 key pair for a token issuer
  pvlt mint-token --seed-file F --key-id N [--caller C] [--subject S] [--role R]... [--purpose P] [--reason T]
                  [--action A]... [--fact UUID] [--scope S] [--resource-subject S] [--grant G]...
                  [--approval ID] [--ttl SECS]
                                            mint a request token (for testing; a real issuer mints its own)
  pvlt audit-verify                         check the audit log's chain and checkpoints (exit 1 if not clean)
  pvlt import-opv --csv FILE --opv-url URL --opv-token-file F --vault-admin-url URL --admin-token-file F
                  --vault-url URL --vault-token-file F [--cacert PEM]... [--state FILE] [--dry-run]
                                            copy facts from an Open Privacy Vault under the same ids
  pvlt version

settings are read from the environment (docs/RUNNING.md)";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rest = args.get(1..).unwrap_or_default();
    let outcome = match args.first().map(String::as_str) {
        Some("init") => runtime.block_on(init(rest)),
        Some("serve") if args.len() == 1 => runtime.block_on(run()),
        Some("backup") => runtime.block_on(backup_cmd(rest)),
        Some("restore") => runtime.block_on(restore_cmd(rest)),
        Some("scrub-backup") => runtime.block_on(scrub_cmd(rest)),
        Some("backup-keygen") if args.len() == 1 => {
            let (secret, recipient) = backup::generate_identity();
            println!("{}", secret.as_str());
            eprintln!(
                "Secret key above (keep it offline and out of the repository). Recipient to give to `pvlt backup`:\n{recipient}"
            );
            Ok(())
        }
        Some("backup-signing-keygen") if args.len() == 1 => match backup::SigningKey::generate() {
            Ok(key) => {
                println!("{}", key.to_hex().as_str());
                eprintln!(
                    "Signing key above (keep it with the backup job only, never with the backups). Give this \
                     public key to `pvlt restore --verify-key`:\n{}",
                    hex::encode(key.public())
                );
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        },
        Some("audit-verify") if args.len() == 1 => runtime.block_on(audit_verify_cmd()),
        Some("import-opv") => runtime.block_on(import_opv_cmd(rest)),
        Some("issuer-keygen") if args.len() == 1 => {
            let (seed, public) = pvlt_server::tokens::generate_issuer_key();
            println!("{}", hex::encode(seed));
            eprintln!(
                "Private seed above (keep it with the issuing service only). Register this public key:\n{}",
                hex::encode(public)
            );
            Ok(())
        }
        Some("mint-token") => mint_cmd(rest),
        Some("version") => {
            println!(
                "pvlt {}{}",
                env!("CARGO_PKG_VERSION"),
                if INSECURE_BUILD {
                    " (dev-insecure)"
                } else {
                    ""
                }
            );
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn number_flag(args: &[String], name: &str, default: u8) -> Result<u8, String> {
    match args.iter().position(|a| a == name) {
        None => Ok(default),
        Some(i) => args
            .get(i + 1)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("{name} needs a number")),
    }
}

/// Every value of a repeatable flag, such as `--recipient`.
fn values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w.first().map(String::as_str) == Some(name))
        .filter_map(|w| w.get(1).cloned())
        .collect()
}

fn one(args: &[String], name: &str) -> Result<PathBuf, String> {
    let all = values(args, name);
    match all.as_slice() {
        [one] => Ok(PathBuf::from(one)),
        _ => Err(format!("give {name} exactly once")),
    }
}

fn mint_cmd(args: &[String]) -> Result<(), String> {
    let seed_hex = std::fs::read_to_string(one(args, "--seed-file")?)
        .map_err(|e| format!("cannot read the seed file: {}", e.kind()))?;
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("the seed file must hold 64 hex characters")?;
    let first = |name: &str| values(args, name).into_iter().next();
    let key_id: u32 = first("--key-id")
        .and_then(|v| v.parse().ok())
        .ok_or("--key-id needs a number")?;
    let ttl: i64 =
        first("--ttl").map_or(Ok(60), |v| v.parse().map_err(|_| "--ttl needs a number"))?;
    let mut request_id = [0u8; 8];
    getrandom::fill(&mut request_id).map_err(|_| "no random numbers")?;
    let claims = pvlt_server::tokens::Claims {
        issuer_key_id: key_id,
        caller: first("--caller"),
        subject: first("--subject"),
        roles: values(args, "--role"),
        purpose: first("--purpose"),
        reason: first("--reason"),
        request_id: hex::encode(request_id),
        actions: values(args, "--action"),
        resource_fact: first("--fact")
            .map(|f| uuid::Uuid::parse_str(&f).map_err(|_| "--fact is not a UUID"))
            .transpose()?,
        resource_scope: first("--scope"),
        resource_subject: first("--resource-subject"),
        grants: values(args, "--grant"),
        approval: first("--approval"),
        expires: time::OffsetDateTime::now_utc().unix_timestamp() + ttl,
    };
    let token = pvlt_server::tokens::mint(&seed, &claims).map_err(|e| e.to_string())?;
    println!("{token}");
    Ok(())
}

fn arena() -> Result<Arena, String> {
    let policy = if INSECURE_BUILD {
        LockPolicy::BestEffort
    } else {
        LockPolicy::Require
    };
    Arena::new(256, policy).map_err(|e| format!("cannot allocate locked key memory: {e}"))
}

async fn connect(url: &str, migrate: bool) -> Result<PgStore, String> {
    let store = PgStore::connect(url, 16)
        .await
        .map_err(|e| format!("key store: {e}"))?;
    if migrate {
        store
            .migrate()
            .await
            .map_err(|e| format!("key store migration: {e}"))?;
    }
    Ok(store)
}

fn objects(config: &Config) -> Result<Objects, String> {
    let data = match &config.storage {
        Storage::S3(s3) => Bucket::s3(s3).map_err(|e| e.to_string())?,
        #[cfg(feature = "dev-insecure")]
        Storage::Directory(dir) => Bucket::local_dir(dir).map_err(|e| e.to_string())?,
    };
    let logs = match &config.ledger_storage {
        Some(s3) => Bucket::s3(s3).map_err(|e| e.to_string())?,
        None => data.clone(),
    };
    Ok(SplitStore { data, logs })
}

fn engine(config: &Config, store: PgStore) -> Result<Server, String> {
    Ok(Engine::new(
        Keyring::new(arena()?),
        store,
        objects(config)?,
        LogAuditor,
        Limits {
            max_value_len: config.max_value_len,
        },
    )
    .with_max_blob_len(config.max_blob_bytes))
}

/// `pvlt init`: creates the root key. The shares go to stdout and nowhere else; the unseal key itself is never
/// stored. Run once.
async fn init(args: &[String]) -> Result<(), String> {
    let threshold = number_flag(args, "--threshold", 3)?;
    let shares = number_flag(args, "--shares", 5)?;
    let config = Config::load_tool(&Env::from_process()).map_err(|e| e.to_string())?;
    let _ = harden_process(false);
    let store = connect(&config.database_url, true).await?;
    let init = init_shamir(&arena()?, threshold, shares).map_err(|e| e.to_string())?;
    match store.init_seal_config(&init.config).await {
        Ok(()) => {}
        Err(StoreError::AlreadyExists) => return Err("this vault is already initialised".into()),
        Err(e) => return Err(e.to_string()),
    }
    eprintln!(
        "Vault initialised. {threshold} of these {shares} shares unseal it. They are shown once and are not \
         stored anywhere: give each to a different person and keep them apart."
    );
    for share in &init.shares {
        println!("{}", share.to_text().as_str());
    }
    Ok(())
}

/// The backup signing key named by `--signing-key-file`.
fn signing_key(args: &[String]) -> Result<backup::SigningKey, String> {
    let text = secret_from_file(&one(args, "--signing-key-file")?)?;
    backup::SigningKey::from_hex(&text).map_err(|e| e.to_string())
}

/// Whom a backup being read must be signed by: `--verify-key HEX`, or `--allow-unsigned` for a backup made
/// before backups were signed.
fn trust(args: &[String]) -> Result<backup::Trust, String> {
    let keys = values(args, "--verify-key");
    let unsigned = args.iter().any(|a| a == "--allow-unsigned");
    match (keys.as_slice(), unsigned) {
        ([key], false) => backup::Trust::signer_hex(key).map_err(|e| e.to_string()),
        ([], true) => {
            eprintln!(
                "warning: --allow-unsigned: nothing proves who made this backup. Use it only for a backup that \
                 predates signed backups and whose origin you know."
            );
            Ok(backup::Trust::Unsigned)
        }
        _ => {
            Err("give --verify-key once (the backup job's public key), or --allow-unsigned".into())
        }
    }
}

/// A database URL from `NAME_FILE` or `NAME` (see `Env::database_url`).
fn database_url(name: &str) -> Result<String, String> {
    Env::from_process()
        .database_url(name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("{name}_FILE or {name} is required"))
}

async fn backup_cmd(args: &[String]) -> Result<(), String> {
    let out = one(args, "--out")?;
    let recipients = values(args, "--recipient");
    let signer = signing_key(args)?;
    let url = database_url("PVLT_DATABASE_URL")?;
    let store = connect(&url, false).await?;
    let rows = tools::backup_to_file(&store, &out, &recipients, &signer)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!("wrote {} ({rows} rows, encrypted)", out.display());
    Ok(())
}

async fn restore_cmd(args: &[String]) -> Result<(), String> {
    let (input, identity) = (one(args, "--in")?, one(args, "--identity")?);
    let trust = trust(args)?;
    let config = Config::load_tool(&Env::from_process()).map_err(|e| e.to_string())?;
    let store = connect(&config.database_url, true).await?;
    tools::must_be_empty(&store)
        .await
        .map_err(|e| e.to_string())?;
    let engine = engine(&config, store.clone())?;
    let report = tools::restore_from_file(&store, &engine, &input, &identity, &trust)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!(
        "restored. Replayed {} ledger entries from the bucket ({} republished). Start the server as usual.",
        report.replayed, report.republished
    );
    Ok(())
}

async fn scrub_cmd(args: &[String]) -> Result<(), String> {
    let (input, identity, out) = (
        one(args, "--in")?,
        one(args, "--identity")?,
        one(args, "--out")?,
    );
    let recipients = values(args, "--recipient");
    let trust = trust(args)?;
    let signer = signing_key(args)?;
    let scratch_url = database_url("PVLT_SCRATCH_DATABASE_URL")
        .map_err(|e| format!("{e}: an empty database to work in"))?;
    let config = Config::load_tool(&Env::from_process()).map_err(|e| e.to_string())?;
    if scratch_url == config.database_url {
        return Err("PVLT_SCRATCH_DATABASE_URL must not be the live database".into());
    }
    let scratch = connect(&scratch_url, true).await?;
    tools::must_be_empty(&scratch)
        .await
        .map_err(|e| e.to_string())?;
    let engine = engine(&config, scratch.clone())?;
    let report = tools::scrub_backup(
        &scratch,
        &engine,
        &input,
        &identity,
        &trust,
        &out,
        &recipients,
        &signer,
    )
    .await
    .map_err(|e| e.to_string())?;
    eprintln!(
        "wrote {}. {} ledger entries were applied that the backup did not have.",
        out.display(),
        report.replayed
    );
    Ok(())
}

fn secret_from_file(path: &std::path::Path) -> Result<zeroize::Zeroizing<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e.kind()))?;
    let trimmed = text.trim_end_matches(['\n', '\r']).to_owned();
    if trimmed.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(zeroize::Zeroizing::new(trimmed))
}

async fn import_opv_cmd(args: &[String]) -> Result<(), String> {
    use pvlt_server::import_opv::{FileState, OpvHttp, VaultHttp, http_client, parse_csv, run};
    let csv_path = one(args, "--csv")?;
    let state_path = values(args, "--state").into_iter().next().map_or_else(
        || PathBuf::from(format!("{}.pvlt-import-state", csv_path.display())),
        PathBuf::from,
    );
    let url = |name: &str| -> Result<String, String> {
        values(args, name)
            .into_iter()
            .next()
            .ok_or_else(|| format!("{name} is required"))
    };
    let (opv_url, admin_url, data_url) = (
        url("--opv-url")?,
        url("--vault-admin-url")?,
        url("--vault-url")?,
    );
    let opv_token = secret_from_file(&one(args, "--opv-token-file")?)?;
    let admin_token = secret_from_file(&one(args, "--admin-token-file")?)?;
    let vault_token = secret_from_file(&one(args, "--vault-token-file")?)?;
    let roots = values(args, "--cacert")
        .iter()
        .map(|p| std::fs::read(p).map_err(|e| format!("cannot read {p}: {}", e.kind())))
        .collect::<Result<Vec<_>, _>>()?;
    let dry_run = args.iter().any(|a| a == "--dry-run");

    let text = std::fs::read_to_string(&csv_path)
        .map_err(|e| format!("cannot read {}: {}", csv_path.display(), e.kind()))?;
    let rows = parse_csv(&text).map_err(|e| e.to_string())?;
    let client = http_client(&roots).map_err(|e| e.to_string())?;
    let source = OpvHttp::new(client.clone(), &opv_url, &opv_token);
    let target = VaultHttp::new(client, &admin_url, &admin_token, &data_url, &vault_token);
    let mut state = FileState::open(&state_path).map_err(|e| {
        format!(
            "cannot open the state file {}: {}",
            state_path.display(),
            e.kind()
        )
    })?;

    eprintln!(
        "importing {} facts{}",
        rows.len(),
        if dry_run {
            " (dry run: nothing will be written)"
        } else {
            ""
        }
    );
    let report = run(&rows, &source, &target, &mut state, dry_run).await;
    eprintln!(
        "total {}  already done {}  imported {}  already there and matching {}  missing in OPV {}  different in the vault {}  failed {}",
        report.total,
        report.already_done,
        report.imported,
        report.already_matching,
        report.missing_in_source.len(),
        report.mismatched.len(),
        report.failed.len()
    );
    for id in &report.missing_in_source {
        eprintln!("missing in OPV: {id}");
    }
    for id in &report.mismatched {
        eprintln!("DIFFERENT in the vault (not changed): {id}");
    }
    for (id, why) in &report.failed {
        eprintln!("failed: {id}: {why}");
    }
    if report.clean() {
        Ok(())
    } else {
        Err("not every fact was imported cleanly; fix the above and run again (finished rows are skipped)".into())
    }
}

async fn audit_verify_cmd() -> Result<(), String> {
    use pvlt_core::engine::AuditStatus;
    let config = Config::load_tool(&Env::from_process()).map_err(|e| e.to_string())?;
    let store = connect(&config.database_url, false).await?;
    let engine = engine(&config, store)?;
    let mut clean = true;
    for domain in engine
        .store()
        .list_domains()
        .await
        .map_err(|e| e.to_string())?
    {
        let v = engine
            .verify_audit(&domain)
            .await
            .map_err(|e| e.to_string())?;
        let name = hex::encode(domain);
        match v.status {
            AuditStatus::Ok => println!(
                "{name}: ok ({} entries, {} checkpoints)",
                v.entries, v.checkpoints
            ),
            AuditStatus::Truncated {
                checkpoint_seq,
                entries,
            } => {
                clean = false;
                println!(
                    "{name}: TRUNCATED: the log has {entries} entries but a signed checkpoint covers up to \
                     {checkpoint_seq}. Entries were lost. Start the server, unseal it, and acknowledge with \
                     POST /v2/admin/audit/acknowledge-rollback if this is a known restore."
                );
            }
            AuditStatus::Tampered(why) => {
                clean = false;
                println!("{name}: TAMPERED: {why}");
            }
        }
    }
    if clean {
        Ok(())
    } else {
        Err("the audit log is not clean".into())
    }
}

async fn run() -> Result<(), String> {
    let config = Config::load(&Env::from_process()).map_err(|e| e.to_string())?;
    if INSECURE_BUILD {
        tracing::warn!("this is a dev-insecure build: do not put real data in it");
    }
    let hardened = harden_process(true);
    if !hardened.all_ok() {
        if INSECURE_BUILD {
            tracing::warn!(?hardened, "process hardening is incomplete");
        } else {
            return Err(format!("process hardening failed: {hardened:?}"));
        }
    }
    if config.ledger_storage.is_none() {
        tracing::warn!(
            "the shred ledger shares the data bucket: if that bucket is restored from a backup, shreds \
             written since are lost with it. Set PVLT_LEDGER_S3_* to a bucket that is never rolled back."
        );
    }

    let store = connect(&config.database_url, true).await?;
    let seal_config = store
        .seal_config()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("the vault is not initialised: run `pvlt init`")?;
    let engine = engine(&config, store)?;

    // Before any listener opens: make the key store agree with the ledger in the bucket. A key store restored
    // from an older backup is re-shredded here; a ledger that fails verification stops the server.
    let report = engine
        .reconcile()
        .await
        .map_err(|e| format!("ledger check failed, refusing to start: {e}"))?;
    tracing::info!(?report, "ledger reconciled");

    // The audit log, checked against its signed checkpoints. A log that was tampered with stops the server. One
    // that lost entries (an older backup was restored) starts, but reads stay off until an admin acknowledges it.
    let audit = engine
        .check_audit()
        .await
        .map_err(|e| format!("audit log check failed, refusing to start: {e}"))?;
    for (domain, v) in &audit {
        tracing::info!(domain = %hex::encode(domain), entries = v.entries, checkpoints = v.checkpoints, status = ?v.status, "audit log checked");
    }
    if engine.audit_blocked() {
        tracing::error!(
            "the audit log lost entries: reads are off until an admin acknowledges it (POST /v2/admin/audit/acknowledge-rollback)"
        );
    }

    let app = Arc::new(
        App::new(
            engine,
            config.domain,
            config.compat_token.as_deref().map(Token::new),
            None,
            seal_config,
        )
        .with_admins(
            config
                .admins
                .iter()
                .map(|(name, token)| Admin {
                    name: name.clone(),
                    token: Token::new(token),
                })
                .collect(),
        )
        .with_access_limits(config.max_token_ttl, config.break_glass)
        .with_blob_limits(config.max_blob_bytes, config.presign_ttl)
        .with_gdpr(config.gdpr),
    );
    app.reload_access()
        .await
        .map_err(|e| format!("cannot load issuers and policy: {e}"))?;
    if app.admins.len() < 2 {
        tracing::warn!(
            "fewer than two admins are configured, so dual-control approvals cannot be granted, and policy and \
             issuer changes take effect on one admin's word"
        );
    }
    let unlimited = app
        .access()
        .policy
        .roles_without_totals()
        .iter()
        .map(|r| (*r).to_owned())
        .collect::<Vec<_>>();
    if !unlimited.is_empty() {
        tracing::warn!(
            roles = ?unlimited,
            "these roles limit each caller but set no total, so an issuer that varies the caller is not held"
        );
    }
    if app.break_glass {
        tracing::warn!(
            "break-glass approvals are enabled: one admin can approve their own emergency read"
        );
    }
    if app.compat_token.is_none() {
        tracing::warn!("no compat token is set, so /api/v1 refuses every request");
    } else if !app.access().policy.has_compat_role() {
        tracing::warn!(
            "the policy has no compat role, so /api/v1 refuses every request until one is set"
        );
    }
    if app.gdpr.enabled {
        tracing::info!(
            export = app.gdpr.export_enabled(),
            admin_inventory = app.gdpr.admin_inventory_enabled(),
            "GDPR mode is on"
        );
    }

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tasks = Vec::new();

    let tls = match &config.tls {
        Some((cert, key)) => Some(load_tls(cert, key).map_err(|e| format!("tls: {e}"))?),
        None => None,
    };
    if let Some(acceptor) = tls {
        let data = TcpListener::bind(config.listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", config.listen))?;
        let admin_listener = TcpListener::bind(config.admin_listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", config.admin_listen))?;
        tracing::info!(data = %config.listen, admin = %config.admin_listen, "listening (TLS 1.3)");
        tasks.push(tokio::spawn(serve(
            data,
            Transport::Tls(acceptor.clone()),
            routes::data_router(Arc::clone(&app)),
            stop_rx.clone(),
        )));
        tasks.push(tokio::spawn(serve(
            admin_listener,
            Transport::Tls(acceptor),
            admin::router(Arc::clone(&app)),
            stop_rx.clone(),
        )));
    }
    #[cfg(feature = "dev-insecure")]
    if let Some(addr) = config.insecure_listen {
        let l = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("cannot listen on {addr}: {e}"))?;
        tracing::warn!(%addr, "PLAINTEXT listener (data and admin routes): development only");
        let both = routes::data_router(Arc::clone(&app)).merge(admin::router(Arc::clone(&app)));
        tasks.push(tokio::spawn(serve(
            l,
            Transport::Plain,
            both,
            stop_rx.clone(),
        )));
    }

    {
        // Other replicas change issuers and policy too; pick their changes up.
        let app = Arc::clone(&app);
        let mut stop = stop_rx.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = stop.changed() => return,
                }
                if let Err(e) = app.reload_access().await {
                    tracing::warn!(error = %e, "reloading issuers and policy failed; keeping the previous ones");
                }
            }
        }));
    }
    {
        // Signed checkpoints of the audit log and the shred ledger go to the log bucket, so truncating or
        // rewriting either can be detected later. They need the root key, so they wait for an unseal.
        let app = Arc::clone(&app);
        let mut stop = stop_rx.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = stop.changed() => return,
                }
                if app.engine.keyring().is_sealed() {
                    continue;
                }
                let hash = app.access().policy_hash;
                match app.engine.write_checkpoints(&hash).await {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(written = n, "checkpoints written"),
                    Err(e) => tracing::warn!(error = %e, "writing checkpoints failed"),
                }
            }
        }));
    }
    if let Some(every) = config.expiry_interval {
        let app = Arc::clone(&app);
        let mut stop = stop_rx.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = stop.changed() => return,
                }
                // Retry ledger entries that did not reach the bucket, then shred what has expired. Signing
                // needs the root key, so while sealed this only retries publishing.
                if let Err(e) = app.engine.publish_pending(&app.domain).await {
                    tracing::warn!(error = %e, "publishing ledger entries failed");
                }
                if app.engine.keyring().is_sealed() {
                    continue;
                }
                loop {
                    match app
                        .engine
                        .sweep_expired("retention", &app.domain, 500)
                        .await
                    {
                        Ok(0) => break,
                        Ok(n) => tracing::info!(shredded = n, "expired facts shredded"),
                        Err(e) => {
                            tracing::warn!(error = %e, "expiry sweep failed");
                            break;
                        }
                    }
                }
            }
        }));
    }
    if let Some(every) = config.sweep_interval {
        let app = Arc::clone(&app);
        let grace = config.sweep_grace;
        let mut stop = stop_rx.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = stop.changed() => return,
                }
                match app
                    .engine
                    .sweep_orphans("sweeper", &app.domain, grace)
                    .await
                {
                    Ok(r) => tracing::info!(?r, "orphan sweep"),
                    Err(e) => tracing::warn!(error = %e, "orphan sweep failed"),
                }
            }
        }));
    }

    stop_signal().await;
    tracing::info!("stopping");
    let _ = stop_tx.send(true);
    for t in tasks {
        let _ = t.await;
    }
    // Wipe the root key and every domain key before the process exits.
    app.seal();
    Ok(())
}
