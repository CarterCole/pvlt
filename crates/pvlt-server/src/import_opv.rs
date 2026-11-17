//! `pvlt import-opv`: moves facts from an Open Privacy Vault into this vault (REQUIREMENTS section 4).
//!
//! The importer is given a CSV of what to move (`id,subject,scope,type`, which the application exports from the
//! columns that hold its fact ids). For each row it reads the value from OPV, writes it to this vault **under the
//! same id** (so the application's stored ids need no rewriting), reads it back through the vault's compat route and
//! compares SHA-256 digests. A row is only marked done once the read-back matches.
//!
//! * **Resumable.** Done ids are appended to a state file; a rerun skips them. A row that was written but not yet
//!   verified is not marked, and on the rerun the vault answers "already exists" and the importer verifies it.
//! * **No plaintext at rest.** Values live in memory in `Zeroizing` strings for one row at a time. The state file
//!   holds ids, the report holds ids and counts, and nothing prints a value.
//! * **Nothing is deleted.** OPV is left as it was. Retiring it is a separate, deliberate step (docs/MIGRATING.md).

use core::fmt;
use core::future::Future;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Why a step failed. A fixed message, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportError(pub String);

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ImportError {}

fn err(m: impl Into<String>) -> ImportError {
    ImportError(m.into())
}

/// One fact to move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The fact id in OPV, kept in this vault.
    pub id: Uuid,
    /// The data subject, as the application names them. May be empty: the fact then has no subject, and a
    /// subject shred will not reach it (REQUIREMENTS C4).
    pub subject: Option<String>,
    /// The scope.
    pub scope: String,
    /// The fact type slug: `ascii`, `printableascii`, `base64` or `json`.
    pub fact_type: String,
}

/// Parses the CSV. The header must be exactly `id,subject,scope,type`. Quoted fields (`"a,b"`, `""`) work.
pub fn parse_csv(text: &str) -> Result<Vec<Row>, ImportError> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    let mut lines = records(text)?.into_iter();
    let header = lines.next().ok_or_else(|| err("the CSV is empty"))?;
    if header != ["id", "subject", "scope", "type"] {
        return Err(err("the CSV header must be exactly: id,subject,scope,type"));
    }
    for (n, rec) in lines.enumerate() {
        let line = n + 2;
        let [id, subject, scope, fact_type] = <[String; 4]>::try_from(rec)
            .map_err(|_| err(format!("line {line}: expected 4 columns")))?;
        let id = Uuid::parse_str(id.trim())
            .map_err(|_| err(format!("line {line}: the id is not a UUID")))?;
        if scope.is_empty() {
            return Err(err(format!("line {line}: the scope is empty")));
        }
        if !matches!(
            fact_type.as_str(),
            "ascii" | "printableascii" | "base64" | "json"
        ) {
            return Err(err(format!(
                "line {line}: the type is not one of ascii, printableascii, base64, json"
            )));
        }
        if !seen.insert(id) {
            return Err(err(format!("line {line}: the id appears twice")));
        }
        rows.push(Row {
            id,
            subject: (!subject.is_empty()).then_some(subject),
            scope,
            fact_type,
        });
    }
    Ok(rows)
}

/// RFC 4180 records: commas, quotes, doubled quotes, and newlines inside quotes.
fn records(text: &str) -> Result<Vec<Vec<String>>, ImportError> {
    let mut out = Vec::new();
    let mut rec: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        any = true;
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            ('"', true) => quoted = false,
            ('"', false) if field.is_empty() => quoted = true,
            (',', false) => rec.push(core::mem::take(&mut field)),
            ('\r', false) => {}
            ('\n', false) => {
                rec.push(core::mem::take(&mut field));
                if !(rec.len() == 1 && rec.first().is_some_and(String::is_empty)) {
                    out.push(core::mem::take(&mut rec));
                } else {
                    rec.clear();
                }
            }
            (c, _) => field.push(c),
        }
    }
    if quoted {
        return Err(err("the CSV has an unterminated quote"));
    }
    if any && (!field.is_empty() || !rec.is_empty()) {
        rec.push(field);
        out.push(rec);
    }
    Ok(out)
}

/// Where values come from.
pub trait Source: Send + Sync {
    /// The value of a fact, or `None` if there is none (a 404).
    fn get(
        &self,
        id: &Uuid,
    ) -> impl Future<Output = Result<Option<Zeroizing<String>>, ImportError>> + Send;
}

/// What writing a fact did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Put {
    /// It was written.
    Created,
    /// The id was already there. The importer checks the stored value matches before it counts the row.
    AlreadyExists,
}

/// Where values go.
pub trait Target: Send + Sync {
    /// Writes a fact under its id.
    fn put(&self, row: &Row, value: &str) -> impl Future<Output = Result<Put, ImportError>> + Send;

    /// Reads a fact back, for the comparison.
    fn get(
        &self,
        id: &Uuid,
    ) -> impl Future<Output = Result<Option<Zeroizing<String>>, ImportError>> + Send;
}

/// Which rows are done.
pub trait State {
    /// Whether a row was already imported and verified.
    fn done(&self, id: &Uuid) -> bool;
    /// Records that a row was imported and verified.
    fn mark(&mut self, id: &Uuid) -> std::io::Result<()>;
}

/// State in memory, for tests and dry runs.
#[derive(Debug, Default)]
pub struct MemState(pub HashSet<Uuid>);

impl State for MemState {
    fn done(&self, id: &Uuid) -> bool {
        self.0.contains(id)
    }
    fn mark(&mut self, id: &Uuid) -> std::io::Result<()> {
        self.0.insert(*id);
        Ok(())
    }
}

/// State in a file, one id per line, flushed to disk before the next row so a crash loses nothing that was marked.
#[derive(Debug)]
pub struct FileState {
    done: HashSet<Uuid>,
    file: std::fs::File,
}

impl FileState {
    /// Opens (creating if needed) the state file and reads the ids already in it.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let existing = std::fs::read_to_string(path).unwrap_or_default();
        let done = existing
            .lines()
            .filter_map(|l| Uuid::parse_str(l.trim()).ok())
            .collect();
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        Ok(Self {
            done,
            file: opts.open(path)?,
        })
    }
}

impl State for FileState {
    fn done(&self, id: &Uuid) -> bool {
        self.done.contains(id)
    }
    fn mark(&mut self, id: &Uuid) -> std::io::Result<()> {
        writeln!(self.file, "{id}")?;
        self.file.sync_data()?;
        self.done.insert(*id);
        Ok(())
    }
}

/// What a run did. Ids and counts only.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// Rows in the CSV.
    pub total: usize,
    /// Skipped because an earlier run finished them.
    pub already_done: usize,
    /// Written now and verified.
    pub imported: usize,
    /// Already in the vault with the same value, verified.
    pub already_matching: usize,
    /// In the CSV but not in OPV.
    pub missing_in_source: Vec<Uuid>,
    /// In the vault with a **different** value than OPV has. Nothing was changed.
    pub mismatched: Vec<Uuid>,
    /// A request failed or the read-back was missing. The reason is a fixed message.
    pub failed: Vec<(Uuid, String)>,
    /// A dry run: nothing was written.
    pub dry_run: bool,
}

impl Report {
    /// Whether every row ended well: nothing missing, mismatched or failed.
    pub fn clean(&self) -> bool {
        self.missing_in_source.is_empty() && self.mismatched.is_empty() && self.failed.is_empty()
    }
}

fn digest(v: &str) -> [u8; 32] {
    Sha256::digest(v.as_bytes()).into()
}

/// Moves the rows. Sequential, one row at a time: this runs once, and a vault under migration is not under load.
pub async fn run<S: Source, T: Target, St: State>(
    rows: &[Row],
    source: &S,
    target: &T,
    state: &mut St,
    dry_run: bool,
) -> Report {
    let mut report = Report {
        total: rows.len(),
        dry_run,
        ..Report::default()
    };
    for row in rows {
        if state.done(&row.id) {
            report.already_done += 1;
            continue;
        }
        let value = match source.get(&row.id).await {
            Ok(Some(v)) => v,
            Ok(None) => {
                report.missing_in_source.push(row.id);
                continue;
            }
            Err(e) => {
                report.failed.push((row.id, e.0));
                continue;
            }
        };
        if dry_run {
            continue;
        }
        let put = match target.put(row, &value).await {
            Ok(p) => p,
            Err(e) => {
                report.failed.push((row.id, e.0));
                continue;
            }
        };
        match target.get(&row.id).await {
            Ok(Some(back)) if digest(&back) == digest(&value) => {
                if let Err(e) = state.mark(&row.id) {
                    report
                        .failed
                        .push((row.id, format!("cannot record progress: {}", e.kind())));
                    continue;
                }
                match put {
                    Put::Created => report.imported += 1,
                    Put::AlreadyExists => report.already_matching += 1,
                }
            }
            Ok(Some(_)) => report.mismatched.push(row.id),
            Ok(None) => report
                .failed
                .push((row.id, "the fact could not be read back".to_owned())),
            Err(e) => report.failed.push((row.id, e.0)),
        }
    }
    report
}

// --- HTTP ---------------------------------------------------------------------------------------------------

/// Builds an HTTP client that trusts the given PEM certificates in addition to the system's.
pub fn http_client(extra_roots_pem: &[Vec<u8>]) -> Result<reqwest::Client, ImportError> {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none());
    for pem in extra_roots_pem {
        let cert = reqwest::Certificate::from_pem(pem)
            .map_err(|_| err("a CA certificate is not valid PEM"))?;
        b = b.add_root_certificate(cert);
    }
    b.build().map_err(|_| err("cannot build the HTTP client"))
}

fn value_of(body: &str) -> Result<Zeroizing<String>, ImportError> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|_| err("the response was not JSON"))?;
    v.get("value")
        .and_then(serde_json::Value::as_str)
        .map(|s| Zeroizing::new(s.to_owned()))
        .ok_or_else(|| err("the response has no value"))
}

/// An OPV (or this vault's compat routes): `GET /api/v1/facts/{id}` with `X-OPV-GRANT-TOKEN`.
pub struct OpvHttp {
    client: reqwest::Client,
    base: String,
    token: Zeroizing<String>,
}

impl OpvHttp {
    /// `base` is a URL like `http://opv-dataplane:28000`.
    pub fn new(client: reqwest::Client, base: &str, token: &str) -> Self {
        Self {
            client,
            base: base.trim_end_matches('/').to_owned(),
            token: Zeroizing::new(token.to_owned()),
        }
    }

    async fn fetch(&self, id: &Uuid) -> Result<Option<Zeroizing<String>>, ImportError> {
        let res = self
            .client
            .get(format!("{}/api/v1/facts/{id}", self.base))
            .header("X-OPV-GRANT-TOKEN", self.token.as_str())
            .send()
            .await
            .map_err(|e| {
                err(format!(
                    "request failed: {}",
                    if e.is_timeout() {
                        "timed out"
                    } else {
                        "could not connect"
                    }
                ))
            })?;
        match res.status().as_u16() {
            200 => {
                let body = Zeroizing::new(
                    res.text()
                        .await
                        .map_err(|_| err("could not read the response"))?,
                );
                value_of(&body).map(Some)
            }
            // A deleted fact is gone for good, and one that never existed is not there: neither can be moved.
            404 | 410 => Ok(None),
            s => Err(err(format!("the server answered {s}"))),
        }
    }
}

impl Source for OpvHttp {
    async fn get(&self, id: &Uuid) -> Result<Option<Zeroizing<String>>, ImportError> {
        self.fetch(id).await
    }
}

/// This vault: writes through the admin import route, reads back through the compat route.
pub struct VaultHttp {
    client: reqwest::Client,
    admin_base: String,
    admin_token: Zeroizing<String>,
    reader: OpvHttp,
}

impl VaultHttp {
    /// `admin_base` is the admin listener, `data_base` the data listener, `compat_token` the `/api/v1` token.
    pub fn new(
        client: reqwest::Client,
        admin_base: &str,
        admin_token: &str,
        data_base: &str,
        compat_token: &str,
    ) -> Self {
        Self {
            admin_base: admin_base.trim_end_matches('/').to_owned(),
            admin_token: Zeroizing::new(admin_token.to_owned()),
            reader: OpvHttp::new(client.clone(), data_base, compat_token),
            client,
        }
    }
}

impl Target for VaultHttp {
    async fn put(&self, row: &Row, value: &str) -> Result<Put, ImportError> {
        let body = Zeroizing::new(
            serde_json::json!({
                "id": row.id,
                "subject": row.subject,
                "scope": row.scope,
                "type": row.fact_type,
                "value": value,
            })
            .to_string(),
        );
        let res = self
            .client
            .post(format!("{}/v2/admin/import/fact", self.admin_base))
            .header(
                "Authorization",
                format!("Bearer {}", self.admin_token.as_str()),
            )
            .header("Content-Type", "application/json")
            .body(body.as_str().to_owned())
            .send()
            .await
            .map_err(|e| {
                err(format!(
                    "request failed: {}",
                    if e.is_timeout() {
                        "timed out"
                    } else {
                        "could not connect"
                    }
                ))
            })?;
        match res.status().as_u16() {
            201 | 200 => Ok(Put::Created),
            409 => Ok(Put::AlreadyExists),
            s => Err(err(format!("the vault answered {s}"))),
        }
    }

    async fn get(&self, id: &Uuid) -> Result<Option<Zeroizing<String>>, ImportError> {
        self.reader.fetch(id).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    const SECRET: &str = "Quentin-Q.-Nightingale-1987-03-09";

    fn id(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    fn row(n: u8) -> Row {
        Row {
            id: id(n),
            subject: Some(format!("user:{n}")),
            scope: "s".into(),
            fact_type: "ascii".into(),
        }
    }

    #[derive(Default)]
    struct Fake {
        data: Mutex<HashMap<Uuid, String>>,
        fail_get: Mutex<HashSet<Uuid>>,
        corrupt_on_put: Mutex<HashSet<Uuid>>,
        fail_put: Mutex<HashSet<Uuid>>,
        puts: Mutex<usize>,
    }

    impl Fake {
        fn with(items: &[(u8, &str)]) -> Self {
            let f = Self::default();
            for (n, v) in items {
                f.data.lock().unwrap().insert(id(*n), (*v).to_owned());
            }
            f
        }
    }

    impl Source for Fake {
        async fn get(&self, i: &Uuid) -> Result<Option<Zeroizing<String>>, ImportError> {
            if self.fail_get.lock().unwrap().contains(i) {
                return Err(err("the server answered 500"));
            }
            Ok(self
                .data
                .lock()
                .unwrap()
                .get(i)
                .map(|v| Zeroizing::new(v.clone())))
        }
    }

    impl Target for Fake {
        async fn put(&self, r: &Row, value: &str) -> Result<Put, ImportError> {
            *self.puts.lock().unwrap() += 1;
            if self.fail_put.lock().unwrap().contains(&r.id) {
                return Err(err("the vault answered 503"));
            }
            let mut d = self.data.lock().unwrap();
            if d.contains_key(&r.id) {
                return Ok(Put::AlreadyExists);
            }
            let stored = if self.corrupt_on_put.lock().unwrap().contains(&r.id) {
                format!("{value}!")
            } else {
                value.to_owned()
            };
            d.insert(r.id, stored);
            Ok(Put::Created)
        }
        async fn get(&self, i: &Uuid) -> Result<Option<Zeroizing<String>>, ImportError> {
            Ok(self
                .data
                .lock()
                .unwrap()
                .get(i)
                .map(|v| Zeroizing::new(v.clone())))
        }
    }

    #[tokio::test]
    async fn rows_are_copied_under_their_own_ids_and_verified() {
        let source = Fake::with(&[(1, "one"), (2, SECRET), (3, "three")]);
        let target = Fake::default();
        let mut state = MemState::default();
        let rows = [row(1), row(2), row(3)];
        let report = run(&rows, &source, &target, &mut state, false).await;
        assert_eq!(
            (report.total, report.imported, report.clean()),
            (3, 3, true)
        );
        assert_eq!(
            target.data.lock().unwrap().get(&id(2)).map(String::as_str),
            Some(SECRET)
        );
        assert_eq!(state.0.len(), 3);
    }

    #[tokio::test]
    async fn a_rerun_skips_what_is_done_and_finishes_what_is_not() {
        let source = Fake::with(&[(1, "one"), (2, "two"), (3, "three")]);
        let target = Fake::default();
        let mut state = MemState::default();
        target.fail_put.lock().unwrap().insert(id(2));
        let first = run(
            &[row(1), row(2), row(3)],
            &source,
            &target,
            &mut state,
            false,
        )
        .await;
        assert_eq!((first.imported, first.failed.len()), (2, 1));
        assert!(!first.clean());

        target.fail_put.lock().unwrap().clear();
        let puts_before = *target.puts.lock().unwrap();
        let second = run(
            &[row(1), row(2), row(3)],
            &source,
            &target,
            &mut state,
            false,
        )
        .await;
        assert_eq!((second.already_done, second.imported), (2, 1));
        assert_eq!(
            *target.puts.lock().unwrap() - puts_before,
            1,
            "only the unfinished row was written again"
        );
        assert!(second.clean());
    }

    #[tokio::test]
    async fn a_row_written_but_not_marked_is_verified_not_duplicated_on_the_rerun() {
        // Simulates a crash after the write and before the mark: the vault has it, the state file does not.
        let source = Fake::with(&[(1, "one")]);
        let target = Fake::default();
        target.data.lock().unwrap().insert(id(1), "one".into());
        let mut state = MemState::default();
        let r = run(&[row(1)], &source, &target, &mut state, false).await;
        assert_eq!((r.imported, r.already_matching, r.clean()), (0, 1, true));
        assert!(state.done(&id(1)));
    }

    #[tokio::test]
    async fn a_different_value_in_the_vault_is_reported_and_never_overwritten_or_marked_done() {
        let source = Fake::with(&[(1, "from-opv"), (2, "x")]);
        let target = Fake::default();
        target
            .data
            .lock()
            .unwrap()
            .insert(id(1), "something-else".into());
        target.corrupt_on_put.lock().unwrap().insert(id(2));
        let mut state = MemState::default();
        let r = run(&[row(1), row(2)], &source, &target, &mut state, false).await;
        assert_eq!(r.mismatched, vec![id(1), id(2)]);
        assert!(!r.clean());
        assert_eq!(
            target.data.lock().unwrap().get(&id(1)).map(String::as_str),
            Some("something-else")
        );
        assert!(
            state.0.is_empty(),
            "a mismatch must be retried, not remembered as done"
        );
    }

    #[tokio::test]
    async fn a_fact_that_is_not_in_the_source_is_reported_and_a_source_error_is_a_failure() {
        let source = Fake::with(&[(2, "two")]);
        source.fail_get.lock().unwrap().insert(id(3));
        let target = Fake::default();
        let mut state = MemState::default();
        let r = run(
            &[row(1), row(2), row(3)],
            &source,
            &target,
            &mut state,
            false,
        )
        .await;
        assert_eq!(r.missing_in_source, vec![id(1)]);
        assert_eq!(r.failed.len(), 1);
        assert_eq!(r.imported, 1);
    }

    #[tokio::test]
    async fn a_dry_run_reads_but_writes_nothing() {
        let source = Fake::with(&[(1, "one")]);
        let target = Fake::default();
        let mut state = MemState::default();
        let r = run(&[row(1), row(2)], &source, &target, &mut state, true).await;
        assert!(r.dry_run);
        assert_eq!(r.missing_in_source, vec![id(2)]);
        assert_eq!(*target.puts.lock().unwrap(), 0);
        assert!(state.0.is_empty());
    }

    #[tokio::test]
    async fn nothing_a_run_reports_or_remembers_holds_a_value() {
        let source = Fake::with(&[(1, SECRET)]);
        source.fail_get.lock().unwrap().insert(id(9));
        let target = Fake::default();
        let mut state = MemState::default();
        let r = run(&[row(1), row(9)], &source, &target, &mut state, false).await;
        assert!(!format!("{r:?}{state:?}").contains("Nightingale"));
    }

    #[test]
    fn the_state_file_survives_a_restart_and_is_private() {
        let dir =
            std::env::temp_dir().join(format!("pvlt-import-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state");
        let mut s = FileState::open(&path).unwrap();
        s.mark(&id(1)).unwrap();
        s.mark(&id(2)).unwrap();
        drop(s);
        let again = FileState::open(&path).unwrap();
        assert!(again.done(&id(1)) && again.done(&id(2)) && !again.done(&id(3)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_csv_is_parsed_strictly() {
        let good = "id,subject,scope,type\n00000000-0000-4000-8000-000000000001,user:1,kyc-doc:1,ascii\n00000000-0000-4000-8000-000000000002,,\"a,b\",json\r\n";
        let rows = parse_csv(good).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].subject.as_deref(), Some("user:1"));
        assert_eq!(
            (rows[1].subject.as_deref(), rows[1].scope.as_str()),
            (None, "a,b")
        );
        for (name, bad) in [
            ("empty", ""),
            ("a wrong header", "id,scope,type,subject\n"),
            (
                "a short row",
                "id,subject,scope,type\n00000000-0000-4000-8000-000000000001,u,s\n",
            ),
            ("a bad id", "id,subject,scope,type\nnot-a-uuid,u,s,ascii\n"),
            (
                "an empty scope",
                "id,subject,scope,type\n00000000-0000-4000-8000-000000000001,u,,ascii\n",
            ),
            (
                "an unknown type",
                "id,subject,scope,type\n00000000-0000-4000-8000-000000000001,u,s,ssn\n",
            ),
            (
                "a repeated id",
                "id,subject,scope,type\n00000000-0000-4000-8000-000000000001,u,s,ascii\n00000000-0000-4000-8000-000000000001,u,s,ascii\n",
            ),
            (
                "an unterminated quote",
                "id,subject,scope,type\n00000000-0000-4000-8000-000000000001,\"u,s,ascii\n",
            ),
        ] {
            assert!(parse_csv(bad).is_err(), "{name} was accepted");
        }
        // Blank lines are ignored and a final line without a newline is read.
        let ok =
            parse_csv("id,subject,scope,type\n\n00000000-0000-4000-8000-000000000001,u,s,ascii")
                .unwrap();
        assert_eq!(ok.len(), 1);
    }
}
