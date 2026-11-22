//! Settings, all from the environment so a container needs no config file. Secrets come from files
//! (`*_FILE`, for Docker and Kubernetes secrets). In a `dev-insecure` build they may also come from the
//! variable itself.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::app::GdprMode;
use crate::bucket::S3Config;
use crate::kms::KmsConfig;
use pvlt_format::Id;
use uuid::Uuid;

/// Where sealed values go.
#[derive(Debug, Clone)]
pub enum Storage {
    /// An S3-compatible bucket.
    S3(S3Config),
    /// A local directory. Development builds only.
    #[cfg(feature = "dev-insecure")]
    Directory(PathBuf),
}

/// Everything the server needs to start.
#[derive(Clone)]
pub struct Config {
    /// The key store's connection URL. Holds a password, so it is never logged.
    pub database_url: String,
    /// The data listener.
    pub listen: SocketAddr,
    /// The admin listener. Loopback by default.
    pub admin_listen: SocketAddr,
    /// The certificate chain and private key, as PEM files.
    pub tls: Option<(PathBuf, PathBuf)>,
    /// Where sealed values go.
    pub storage: Storage,
    /// A separate bucket for the ledger, which must never be restored from a backup (`PVLT_LEDGER_S3_*`). If
    /// unset the ledger shares the data bucket, which is weaker: see docs/RUNNING.md.
    pub ledger_storage: Option<S3Config>,
    /// The domain the compat token maps to.
    pub domain: Id,
    /// The static `/api/v1` token.
    pub compat_token: Option<String>,
    /// Named administrators as `(name, token)`. From `PVLT_ADMIN_TOKENS_FILE` (one `name:token` per line) or, for
    /// a single admin named `admin`, `PVLT_ADMIN_TOKEN(_FILE)`. Dual control needs two.
    pub admins: Vec<(String, String)>,
    /// The largest blob in plaintext bytes (`PVLT_MAX_BLOB_BYTES`, default 256 MiB).
    pub max_blob_bytes: u64,
    /// How long a presigned upload or download address lives (`PVLT_PRESIGN_TTL_SECS`, default 900).
    pub presign_ttl: Duration,
    /// The longest a request token may live, in seconds (`PVLT_MAX_TOKEN_TTL_SECS`, default 300).
    pub max_token_ttl: i64,
    /// Whether one admin may approve their own emergency read (`PVLT_BREAK_GLASS=true`).
    pub break_glass: bool,
    /// The longest fact value accepted.
    pub max_value_len: usize,
    /// How often expired facts are shredded and unpublished ledger entries retried. `None` turns it off.
    pub expiry_interval: Option<Duration>,
    /// How often the orphan sweeper runs. `None` turns it off.
    pub sweep_interval: Option<Duration>,
    /// How old an unkeyed object must be before the sweeper may delete it.
    pub sweep_grace: Duration,
    /// GDPR mode and which of its parts are on (`PVLT_GDPR_MODE`, `PVLT_GDPR_EXPORT`,
    /// `PVLT_GDPR_ADMIN_INVENTORY`).
    pub gdpr: GdprMode,
    /// The KMS that holds a wrapped copy of the unseal key, for auto-unseal (`PVLT_KMS_KEY_ID`, `PVLT_KMS_REGION`,
    /// `PVLT_KMS_ENDPOINT`, `PVLT_KMS_ALLOW_HTTP`). `None`: unseal by hand with shares.
    pub kms: Option<KmsConfig>,
    /// A plaintext data listener. Development builds only.
    #[cfg(feature = "dev-insecure")]
    pub insecure_listen: Option<SocketAddr>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("admin_listen", &self.admin_listen)
            .field("domain", &Uuid::from_bytes(self.domain))
            .field("storage", &self.storage)
            .finish_non_exhaustive()
    }
}

/// Why the settings are not usable. The text names a variable, never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn bad(msg: impl Into<String>) -> ConfigError {
    ConfigError(msg.into())
}

/// A source of settings. `std::env::vars` in `main`, a map in tests.
pub struct Env(HashMap<String, String>);

impl Env {
    /// The process environment.
    pub fn from_process() -> Self {
        Self(std::env::vars().collect())
    }

    /// A fixed set, for tests.
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    fn require(&self, name: &str) -> Result<&str, ConfigError> {
        self.get(name)
            .ok_or_else(|| bad(format!("{name} is required")))
    }

    /// A secret: from `NAME_FILE` (trailing newline removed), or in a development build from `NAME`.
    fn secret(&self, name: &str) -> Result<Option<String>, ConfigError> {
        let file_var = format!("{name}_FILE");
        if let Some(path) = self.get(&file_var) {
            let text = std::fs::read_to_string(path)
                .map_err(|e| bad(format!("{file_var}: cannot read the file: {}", e.kind())))?;
            let text = text.trim_end_matches(['\n', '\r']).to_owned();
            if text.is_empty() {
                return Err(bad(format!("{file_var}: the file is empty")));
            }
            return Ok(Some(text));
        }
        if let Some(value) = self.get(name) {
            #[cfg(feature = "dev-insecure")]
            return Ok(Some(value.to_owned()));
            #[cfg(not(feature = "dev-insecure"))]
            {
                let _ = value;
                return Err(bad(format!(
                    "{name} is not accepted in this build; put it in a file and set {file_var}"
                )));
            }
        }
        Ok(None)
    }

    /// A Postgres connection URL: from `NAME_FILE`, or from `NAME` itself if it carries no password (one that
    /// uses a client certificate, a `.pgpass` file or peer authentication). A default build refuses a password
    /// in the variable, where it would show up in the process environment and in `docker inspect`.
    pub fn database_url(&self, name: &str) -> Result<Option<String>, ConfigError> {
        let file_var = format!("{name}_FILE");
        if self.get(&file_var).is_some() {
            return self.secret(name);
        }
        match self.get(name) {
            None => Ok(None),
            Some(url) if INSECURE || !url_has_password(url) => Ok(Some(url.to_owned())),
            Some(_) => Err(bad(format!(
                "{name} holds a password, which this build does not take from a variable; put the URL in a \
                 file and set {file_var}"
            ))),
        }
    }

    /// An S3 bucket's settings from `<prefix>_BUCKET`, `_REGION`, `_ENDPOINT`, `_ACCESS_KEY_ID(_FILE)`,
    /// `_SECRET_ACCESS_KEY(_FILE)`, `_ALLOW_HTTP` and `_PATH_STYLE`. `None` if `<prefix>_BUCKET` is unset.
    fn s3(&self, prefix: &str) -> Result<Option<S3Config>, ConfigError> {
        let Some(bucket) = self.get(&format!("{prefix}_BUCKET")) else {
            return Ok(None);
        };
        let key_id = format!("{prefix}_ACCESS_KEY_ID");
        let secret = format!("{prefix}_SECRET_ACCESS_KEY");
        Ok(Some(S3Config {
            bucket: bucket.to_owned(),
            region: self
                .get(&format!("{prefix}_REGION"))
                .unwrap_or("us-east-1")
                .to_owned(),
            endpoint: self.get(&format!("{prefix}_ENDPOINT")).map(str::to_owned),
            access_key_id: self
                .secret(&key_id)?
                .ok_or_else(|| bad(format!("{key_id}_FILE is required")))?,
            secret_access_key: self
                .secret(&secret)?
                .ok_or_else(|| bad(format!("{secret}_FILE is required")))?,
            allow_http: self.flag(&format!("{prefix}_ALLOW_HTTP"))?,
            path_style: self.flag(&format!("{prefix}_PATH_STYLE"))?,
        }))
    }

    fn addr(&self, name: &str, default: &str) -> Result<SocketAddr, ConfigError> {
        self.get(name)
            .unwrap_or(default)
            .parse()
            .map_err(|_| bad(format!("{name} is not an address like 127.0.0.1:8443")))
    }

    fn number(&self, name: &str, default: u64) -> Result<u64, ConfigError> {
        match self.get(name) {
            None => Ok(default),
            Some(v) => v
                .parse()
                .map_err(|_| bad(format!("{name} is not a whole number"))),
        }
    }

    /// The KMS settings, if `PVLT_KMS_KEY_ID` is set. A plain `http` endpoint needs `PVLT_KMS_ALLOW_HTTP=true`:
    /// the key material crosses it.
    fn kms(&self) -> Result<Option<KmsConfig>, ConfigError> {
        let Some(key_id) = self.get("PVLT_KMS_KEY_ID") else {
            return Ok(None);
        };
        let endpoint = self.get("PVLT_KMS_ENDPOINT").map(str::to_owned);
        if let Some(e) = &endpoint
            && !e.starts_with("https://")
            && !(e.starts_with("http://") && self.flag("PVLT_KMS_ALLOW_HTTP")?)
        {
            return Err(bad(
                "PVLT_KMS_ENDPOINT must be https:// (or http:// with PVLT_KMS_ALLOW_HTTP=true on a private network)",
            ));
        }
        Ok(Some(KmsConfig {
            key_id: key_id.to_owned(),
            region: self.get("PVLT_KMS_REGION").map(str::to_owned),
            endpoint,
        }))
    }

    fn flag(&self, name: &str) -> Result<bool, ConfigError> {
        self.flag_or(name, false)
    }

    fn flag_or(&self, name: &str, default: bool) -> Result<bool, ConfigError> {
        match self.get(name) {
            None => Ok(default),
            Some("0" | "false") => Ok(false),
            Some("1" | "true") => Ok(true),
            Some(_) => Err(bad(format!("{name} must be true or false"))),
        }
    }
}

const INSECURE: bool = cfg!(feature = "dev-insecure");

/// The shortest static token accepted: the compat token and every admin token.
pub const MIN_TOKEN_LEN: usize = 16;

/// Whether a Postgres connection URL carries a password, in its user info (`user:password@`) or as a
/// `password=` parameter.
pub fn url_has_password(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end).unwrap_or(rest);
    let in_userinfo = authority
        .rsplit_once('@')
        .is_some_and(|(userinfo, _)| userinfo.contains(':'));
    let in_query = rest.split_once('?').is_some_and(|(_, q)| {
        q.split(['&', '#'])
            .filter_map(|kv| kv.split('=').next())
            .any(|k| k.eq_ignore_ascii_case("password"))
    });
    in_userinfo || in_query
}

/// Reads the administrators. Names must be unique and plain, and no two admins may share a token: dual control
/// means two people.
fn admins(env: &Env) -> Result<Vec<(String, String)>, ConfigError> {
    let mut out: Vec<(String, String)> = Vec::new();
    if let Some(single) = env.secret("PVLT_ADMIN_TOKEN")? {
        out.push(("admin".to_owned(), single));
    }
    if let Some(path) = env.get("PVLT_ADMIN_TOKENS_FILE") {
        let text = std::fs::read_to_string(path).map_err(|e| {
            bad(format!(
                "PVLT_ADMIN_TOKENS_FILE: cannot read the file: {}",
                e.kind()
            ))
        })?;
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let (name, token) = line
                .split_once(':')
                .ok_or_else(|| bad("PVLT_ADMIN_TOKENS_FILE: each line must be name:token"))?;
            out.push((name.to_owned(), token.to_owned()));
        }
    }
    for (name, token) in &out {
        let plain = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'));
        if !plain {
            return Err(bad(
                "an admin name must be 1 to 64 letters, digits, - _ or .",
            ));
        }
        if token.len() < MIN_TOKEN_LEN {
            return Err(bad("an admin token must be at least 16 characters"));
        }
    }
    for (i, (name, token)) in out.iter().enumerate() {
        if out.iter().skip(i + 1).any(|(n, t)| n == name || t == token) {
            return Err(bad("admin names and tokens must each be unique"));
        }
    }
    Ok(out)
}

impl Config {
    /// Reads the settings for the server, which needs TLS.
    pub fn load(env: &Env) -> Result<Self, ConfigError> {
        Self::load_with(env, true)
    }

    /// Reads the settings for a command that does not listen (`init`, `backup`, `restore`): TLS is not needed.
    pub fn load_tool(env: &Env) -> Result<Self, ConfigError> {
        Self::load_with(env, false)
    }

    fn load_with(env: &Env, serve: bool) -> Result<Self, ConfigError> {
        let domain = Uuid::parse_str(env.require("PVLT_DOMAIN")?)
            .map_err(|_| bad("PVLT_DOMAIN is not a UUID"))?
            .into_bytes();

        let storage = match env.get("PVLT_DATA_DIR") {
            Some(_dir) => {
                #[cfg(feature = "dev-insecure")]
                {
                    Storage::Directory(PathBuf::from(_dir))
                }
                #[cfg(not(feature = "dev-insecure"))]
                return Err(bad(
                    "PVLT_DATA_DIR is not accepted in this build; use an S3 bucket",
                ));
            }
            None => Storage::S3(
                env.s3("PVLT_S3")?
                    .ok_or_else(|| bad("PVLT_S3_BUCKET is required"))?,
            ),
        };
        let ledger_storage = env.s3("PVLT_LEDGER_S3")?;

        let tls = match (env.get("PVLT_TLS_CERT"), env.get("PVLT_TLS_KEY")) {
            (Some(c), Some(k)) => Some((PathBuf::from(c), PathBuf::from(k))),
            (None, None) => None,
            _ => return Err(bad("PVLT_TLS_CERT and PVLT_TLS_KEY go together")),
        };
        #[cfg(feature = "dev-insecure")]
        let insecure_listen = env
            .get("PVLT_INSECURE_DEV_LISTEN")
            .map(|_| env.addr("PVLT_INSECURE_DEV_LISTEN", "127.0.0.1:8080"))
            .transpose()?;
        #[cfg(feature = "dev-insecure")]
        let plain = insecure_listen.is_some();
        #[cfg(not(feature = "dev-insecure"))]
        let plain = false;
        if serve && tls.is_none() && !plain {
            return Err(bad(
                "PVLT_TLS_CERT and PVLT_TLS_KEY are required: there is no plaintext listener in this build",
            ));
        }

        let max_value_len = usize::try_from(env.number("PVLT_MAX_VALUE_BYTES", 1_048_576)?)
            .map_err(|_| bad("PVLT_MAX_VALUE_BYTES is too large"))?;
        let sweep_secs = env.number("PVLT_SWEEP_INTERVAL_SECS", 3600)?;
        let compat_token = env.secret("PVLT_COMPAT_TOKEN")?;
        if compat_token
            .as_ref()
            .is_some_and(|t| t.len() < MIN_TOKEN_LEN)
        {
            return Err(bad("the compat token must be at least 16 characters"));
        }

        Ok(Self {
            database_url: env
                .database_url("PVLT_DATABASE_URL")?
                .ok_or_else(|| bad("PVLT_DATABASE_URL_FILE or PVLT_DATABASE_URL is required"))?,
            listen: env.addr("PVLT_LISTEN", "0.0.0.0:8443")?,
            admin_listen: env.addr("PVLT_ADMIN_LISTEN", "127.0.0.1:8444")?,
            tls,
            storage,
            ledger_storage,
            domain,
            compat_token,
            admins: admins(env)?,
            max_token_ttl: i64::try_from(env.number("PVLT_MAX_TOKEN_TTL_SECS", 300)?)
                .map_err(|_| bad("PVLT_MAX_TOKEN_TTL_SECS is too large"))?,
            break_glass: env.flag("PVLT_BREAK_GLASS")?,
            max_blob_bytes: env.number("PVLT_MAX_BLOB_BYTES", 256 * 1024 * 1024)?,
            presign_ttl: Duration::from_secs(
                env.number("PVLT_PRESIGN_TTL_SECS", 900)?.clamp(30, 3600),
            ),
            max_value_len,
            expiry_interval: {
                let secs = env.number("PVLT_EXPIRY_INTERVAL_SECS", 300)?;
                (secs > 0).then(|| Duration::from_secs(secs))
            },
            sweep_interval: (sweep_secs > 0).then(|| Duration::from_secs(sweep_secs)),
            sweep_grace: Duration::from_secs(env.number("PVLT_SWEEP_GRACE_SECS", 3600)?),
            gdpr: GdprMode {
                enabled: env.flag("PVLT_GDPR_MODE")?,
                export: env.flag_or("PVLT_GDPR_EXPORT", true)?,
                admin_inventory: env.flag_or("PVLT_GDPR_ADMIN_INVENTORY", true)?,
            },
            kms: env.kms()?,
            #[cfg(feature = "dev-insecure")]
            insecure_listen,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const DOMAIN: &str = "11111111-1111-4111-8111-111111111111";

    /// Secret files in a scratch directory, removed when dropped.
    struct Files(std::path::PathBuf);

    impl Files {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir()
                .join(format!("pvlt-config-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            for (name, text) in [("key-id", "AKID\n"), ("secret", "SECRET\n")] {
                std::fs::write(dir.join(name), text).unwrap();
            }
            Self(dir)
        }

        fn path(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }
    }

    impl Drop for Files {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A complete, valid set of settings.
    fn base(files: &Files) -> Vec<(String, String)> {
        [
            ("PVLT_DATABASE_URL", "postgres://u@h/db".to_owned()),
            ("PVLT_DOMAIN", DOMAIN.to_owned()),
            ("PVLT_S3_BUCKET", "b".to_owned()),
            ("PVLT_S3_ACCESS_KEY_ID_FILE", files.path("key-id")),
            ("PVLT_S3_SECRET_ACCESS_KEY_FILE", files.path("secret")),
            ("PVLT_TLS_CERT", "c.pem".to_owned()),
            ("PVLT_TLS_KEY", "k.pem".to_owned()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
    }

    fn env(pairs: &[(String, String)]) -> Env {
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        Env::from_pairs(&borrowed)
    }

    fn without(mut pairs: Vec<(String, String)>, drop: &str) -> Vec<(String, String)> {
        pairs.retain(|(k, _)| !k.starts_with(drop));
        pairs
    }

    fn with(mut pairs: Vec<(String, String)>, key: &str, value: &str) -> Vec<(String, String)> {
        pairs.retain(|(k, _)| k != key);
        pairs.push((key.to_owned(), value.to_owned()));
        pairs
    }

    #[test]
    #[allow(clippy::infallible_destructuring_match)] // the dev-insecure build has a second variant
    fn a_complete_set_loads_and_secrets_come_from_files_without_the_newline() {
        let f = Files::new("ok");
        let c = Config::load(&env(&base(&f))).unwrap();
        let s3 = match &c.storage {
            Storage::S3(s3) => s3,
            #[cfg(feature = "dev-insecure")]
            Storage::Directory(_) => panic!("expected S3"),
        };
        assert_eq!(
            (s3.access_key_id.as_str(), s3.secret_access_key.as_str()),
            ("AKID", "SECRET")
        );
        assert_eq!(c.domain, Uuid::parse_str(DOMAIN).unwrap().into_bytes());
        assert_eq!(c.listen.port(), 8443);
        assert!(c.admin_listen.ip().is_loopback());
    }

    #[test]
    fn a_missing_secret_file_is_named_without_its_content() {
        let f = Files::new("missing");
        let pairs = with(base(&f), "PVLT_S3_ACCESS_KEY_ID_FILE", "/nonexistent/key");
        let err = Config::load(&env(&pairs)).unwrap_err();
        assert!(err.0.contains("PVLT_S3_ACCESS_KEY_ID_FILE"), "{err}");
    }

    #[test]
    fn tls_is_required_without_a_dev_listener() {
        let f = Files::new("tls");
        let err = Config::load(&env(&without(base(&f), "PVLT_TLS"))).unwrap_err();
        assert!(err.0.contains("PVLT_TLS_CERT"), "{err}");
    }

    #[test]
    fn a_cert_without_a_key_is_refused() {
        let f = Files::new("half");
        let err = Config::load(&env(&without(base(&f), "PVLT_TLS_KEY"))).unwrap_err();
        assert!(err.0.contains("go together"), "{err}");
    }

    #[test]
    fn a_bad_domain_is_refused_and_not_echoed() {
        let f = Files::new("domain");
        let err = Config::load(&env(&with(base(&f), "PVLT_DOMAIN", "hunter2"))).unwrap_err();
        assert!(
            err.0.contains("PVLT_DOMAIN") && !err.0.contains("hunter2"),
            "{err}"
        );
    }

    #[test]
    fn an_empty_secret_file_is_refused() {
        let f = Files::new("empty");
        std::fs::write(f.0.join("secret"), "\n").unwrap();
        let err = Config::load(&env(&base(&f))).unwrap_err();
        assert!(err.0.contains("empty"), "{err}");
    }

    #[test]
    fn gdpr_mode_is_off_by_default_and_its_intrusive_parts_can_be_turned_off_one_by_one() {
        let f = Files::new("gdpr");
        let off = Config::load(&env(&base(&f))).unwrap().gdpr;
        assert!(!off.enabled && !off.export_enabled() && !off.admin_inventory_enabled());

        let on = Config::load(&env(&with(base(&f), "PVLT_GDPR_MODE", "true")))
            .unwrap()
            .gdpr;
        assert_eq!(on, GdprMode::on());

        let pairs = with(
            with(base(&f), "PVLT_GDPR_MODE", "true"),
            "PVLT_GDPR_ADMIN_INVENTORY",
            "false",
        );
        let pairs = with(pairs, "PVLT_GDPR_EXPORT", "0");
        let narrow = Config::load(&env(&pairs)).unwrap().gdpr;
        assert!(narrow.enabled && !narrow.export_enabled() && !narrow.admin_inventory_enabled());

        let err = Config::load(&env(&with(base(&f), "PVLT_GDPR_MODE", "yes"))).unwrap_err();
        assert!(err.0.contains("PVLT_GDPR_MODE"), "{err}");
    }

    #[test]
    fn a_password_in_a_connection_url_is_found() {
        for with in [
            "postgres://u:p@h/db",
            "postgresql://u:p%40ss@h:5432/db?sslmode=verify-full",
            "postgres://u@h/db?sslmode=require&password=x",
            "postgres://u@h/db?PASSWORD=x",
        ] {
            assert!(url_has_password(with), "{with}");
        }
        for without in [
            "postgres://u@h/db",
            "postgres://h/db",
            "postgres://u@h/db?sslmode=verify-full&sslcert=/c.pem",
            // A colon after the host is a port, not a password.
            "postgres://u@h:5432/db",
            "postgres://h:5432/db?application_name=a:b",
        ] {
            assert!(!url_has_password(without), "{without}");
        }
    }

    #[test]
    fn the_database_url_comes_from_a_file_with_its_password() {
        let f = Files::new("db");
        std::fs::write(f.0.join("db-url"), "postgres://u:secret@h/db\n").unwrap();
        let pairs = with(
            without(base(&f), "PVLT_DATABASE_URL"),
            "PVLT_DATABASE_URL_FILE",
            &f.path("db-url"),
        );
        assert_eq!(
            Config::load(&env(&pairs)).unwrap().database_url,
            "postgres://u:secret@h/db"
        );
        let err = Config::load(&env(&without(base(&f), "PVLT_DATABASE_URL"))).unwrap_err();
        assert!(err.0.contains("PVLT_DATABASE_URL"), "{err}");
    }

    #[test]
    fn a_short_compat_token_is_refused() {
        let f = Files::new("compat");
        std::fs::write(f.0.join("compat"), "short\n").unwrap();
        let pairs = with(base(&f), "PVLT_COMPAT_TOKEN_FILE", &f.path("compat"));
        let err = Config::load(&env(&pairs)).unwrap_err();
        assert!(
            err.0.contains("compat token") && !err.0.contains("short"),
            "{err}"
        );
    }

    #[cfg(not(feature = "dev-insecure"))]
    #[test]
    fn a_default_build_refuses_secrets_in_variables_and_a_local_directory() {
        let f = Files::new("pw");
        let err = Config::load(&env(&with(
            base(&f),
            "PVLT_DATABASE_URL",
            "postgres://u:hunter2@h/db",
        )))
        .unwrap_err();
        assert!(
            err.0.contains("PVLT_DATABASE_URL_FILE") && !err.0.contains("hunter2"),
            "{err}"
        );

        let f = Files::new("strict");
        let err =
            Config::load(&env(&with(base(&f), "PVLT_COMPAT_TOKEN", "abc-token"))).unwrap_err();
        assert!(
            err.0.contains("PVLT_COMPAT_TOKEN") && !err.0.contains("abc-token"),
            "{err}"
        );

        let err = Config::load(&env(&with(base(&f), "PVLT_DATA_DIR", "/tmp/x"))).unwrap_err();
        assert!(err.0.contains("PVLT_DATA_DIR"), "{err}");

        // A plaintext listener cannot even be asked for.
        let asked = with(
            without(base(&f), "PVLT_TLS"),
            "PVLT_INSECURE_DEV_LISTEN",
            "127.0.0.1:1",
        );
        assert!(Config::load(&env(&asked)).is_err());
    }

    #[cfg(feature = "dev-insecure")]
    #[test]
    fn a_dev_build_accepts_a_variable_a_directory_and_a_plaintext_listener() {
        let f = Files::new("dev");
        let pairs = with(base(&f), "PVLT_COMPAT_TOKEN", "abc-token-0123456789");
        assert_eq!(
            Config::load(&env(&pairs)).unwrap().compat_token.as_deref(),
            Some("abc-token-0123456789")
        );
        let dev = with(
            with(without(base(&f), "PVLT_TLS"), "PVLT_DATA_DIR", "/tmp/x"),
            "PVLT_INSECURE_DEV_LISTEN",
            "127.0.0.1:9",
        );
        let c = Config::load(&env(&dev)).unwrap();
        assert!(matches!(c.storage, Storage::Directory(_)));
        assert_eq!(c.insecure_listen.map(|a| a.port()), Some(9));
    }

    #[test]
    fn kms_is_off_unless_a_key_is_named_and_a_plain_http_endpoint_needs_a_flag() {
        let files = Files::new("kms");
        assert_eq!(Config::load(&env(&base(&files))).unwrap().kms, None);

        let on = with(base(&files), "PVLT_KMS_KEY_ID", "alias/pvlt-unseal");
        let kms = Config::load(&env(&on)).unwrap().kms.unwrap();
        assert_eq!(kms.key_id, "alias/pvlt-unseal");
        assert_eq!((kms.region, kms.endpoint), (None, None));

        let http = with(on.clone(), "PVLT_KMS_ENDPOINT", "http://kms.internal:8080");
        let err = Config::load(&env(&http)).unwrap_err().to_string();
        assert!(err.contains("PVLT_KMS_ENDPOINT must be https://"), "{err}");
        let allowed = with(http, "PVLT_KMS_ALLOW_HTTP", "true");
        assert!(Config::load(&env(&allowed)).unwrap().kms.is_some());
        let https = with(on, "PVLT_KMS_ENDPOINT", "https://kms.vpce.example.com");
        assert!(Config::load(&env(&https)).unwrap().kms.is_some());
    }
}
