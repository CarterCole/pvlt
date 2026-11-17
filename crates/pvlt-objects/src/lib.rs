//! The object store backed by the `object_store` crate: S3-compatible buckets (AWS, MinIO, R2, B2) and a local
//! directory for development. In-memory is here too, for tests of code that wants the same interface.
//!
//! Implements [`pvlt_core::objects::ObjectStore`]. What goes in a bucket is sealed ciphertext under a random
//! id (FORMAT.md section 7), so this crate never sees a key or a plaintext.
//!
//! Not enforced here: FORMAT.md asks that writers set no metadata and no `Content-Type` beyond
//! `application/octet-stream`. This crate sets none, so the S3 service applies its own default. That has not
//! been checked against a live bucket (no S3 service was available when this was written).

use std::fmt;
use std::sync::Arc;

use futures::TryStreamExt;
use object_store::path::Path;
use object_store::{ObjectStore as Backend, ObjectStoreExt, PutPayload};
use pvlt_core::objects::{ObjectError, ObjectInfo, ObjectStore};
use time::OffsetDateTime;

/// How to reach an S3-compatible bucket.
#[derive(Clone)]
pub struct S3Config {
    /// The bucket name.
    pub bucket: String,
    /// The region. MinIO accepts any value, such as `us-east-1`.
    pub region: String,
    /// The service URL. `None` means AWS.
    pub endpoint: Option<String>,
    /// The access key id.
    pub access_key_id: String,
    /// The secret access key.
    pub secret_access_key: String,
    /// Allow a plain `http://` endpoint. For a MinIO container on a private network only.
    pub allow_http: bool,
    /// Use `https://endpoint/bucket/key` and not `https://bucket.endpoint/key`. MinIO needs this.
    pub path_style: bool,
}

impl fmt::Debug for S3Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Config")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("access_key_id", &"..")
            .field("secret_access_key", &"..")
            .field("allow_http", &self.allow_http)
            .field("path_style", &self.path_style)
            .finish()
    }
}

/// A bucket.
#[derive(Clone)]
pub struct Bucket {
    inner: Arc<dyn Backend>,
    /// The same bucket as an S3 client, kept to make presigned URLs. `None` for a directory or memory.
    s3: Option<Arc<object_store::aws::AmazonS3>>,
}

impl fmt::Debug for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bucket({})", self.inner)
    }
}

fn err(e: object_store::Error) -> ObjectError {
    // The driver's text names a path and a status, never object contents.
    ObjectError(e.to_string())
}

impl Bucket {
    /// A bucket in memory. Gone when the process exits.
    pub fn in_memory() -> Self {
        Self {
            inner: Arc::new(object_store::memory::InMemory::new()),
            s3: None,
        }
    }

    /// A bucket in a local directory, which must exist. Development only: a directory cannot presign, and it
    /// has none of a bucket's durability.
    pub fn local_dir(dir: &std::path::Path) -> Result<Self, ObjectError> {
        let fs = object_store::local::LocalFileSystem::new_with_prefix(dir).map_err(err)?;
        Ok(Self {
            inner: Arc::new(fs),
            s3: None,
        })
    }

    /// An S3-compatible bucket.
    pub fn s3(config: &S3Config) -> Result<Self, ObjectError> {
        let mut builder = object_store::aws::AmazonS3Builder::new()
            .with_bucket_name(&config.bucket)
            .with_region(&config.region)
            .with_access_key_id(&config.access_key_id)
            .with_secret_access_key(&config.secret_access_key)
            .with_allow_http(config.allow_http)
            .with_virtual_hosted_style_request(!config.path_style);
        if let Some(endpoint) = &config.endpoint {
            builder = builder.with_endpoint(endpoint);
        }
        let s3 = Arc::new(builder.build().map_err(err)?);
        Ok(Self {
            inner: Arc::clone(&s3) as Arc<dyn Backend>,
            s3: Some(s3),
        })
    }
}

impl Bucket {
    async fn presign(
        &self,
        path: &str,
        ttl: std::time::Duration,
        method: object_store::signer::Method,
    ) -> Result<Option<String>, ObjectError> {
        use object_store::signer::Signer;
        let Some(s3) = &self.s3 else {
            return Ok(None);
        };
        s3.signed_url(method, &Path::from(path), ttl)
            .await
            .map(|u| Some(u.to_string()))
            .map_err(err)
    }
}

fn to_time(t: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(t).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

impl ObjectStore for Bucket {
    async fn ping(&self) -> Result<(), ObjectError> {
        // A read of a key that is never written: "not found" proves the bucket answered and we may read it.
        match self.inner.head(&Path::from("v1/.ping")).await {
            Ok(_) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(err(e)),
        }
    }

    async fn put_path(&self, path: &str, bytes: Vec<u8>) -> Result<(), ObjectError> {
        self.inner
            .put(&Path::from(path), PutPayload::from(bytes))
            .await
            .map(|_| ())
            .map_err(err)
    }

    async fn get_path(&self, path: &str) -> Result<Option<Vec<u8>>, ObjectError> {
        match self.inner.get(&Path::from(path)).await {
            Ok(got) => Ok(Some(got.bytes().await.map_err(err)?.to_vec())),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(err(e)),
        }
    }

    async fn delete_path(&self, path: &str) -> Result<(), ObjectError> {
        match self.inner.delete(&Path::from(path)).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(err(e)),
        }
    }

    async fn head_path(&self, path: &str) -> Result<Option<u64>, ObjectError> {
        match self.inner.head(&Path::from(path)).await {
            Ok(meta) => Ok(Some(meta.size)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(err(e)),
        }
    }

    async fn get_range(
        &self,
        path: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<Vec<u8>>, ObjectError> {
        let p = Path::from(path);
        let size = match self.inner.head(&p).await {
            Ok(meta) => meta.size,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(err(e)),
        };
        let end = start.saturating_add(len).min(size);
        if start >= end {
            return Ok(Some(Vec::new()));
        }
        self.inner
            .get_range(&p, start..end)
            .await
            .map(|b| Some(b.to_vec()))
            .map_err(err)
    }

    async fn presign_put(
        &self,
        path: &str,
        ttl: std::time::Duration,
    ) -> Result<Option<String>, ObjectError> {
        self.presign(path, ttl, object_store::signer::Method::PUT)
            .await
    }

    async fn presign_get(
        &self,
        path: &str,
        ttl: std::time::Duration,
    ) -> Result<Option<String>, ObjectError> {
        self.presign(path, ttl, object_store::signer::Method::GET)
            .await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, ObjectInfo)>, ObjectError> {
        let metas: Vec<object_store::ObjectMeta> = self
            .inner
            .list(Some(&Path::from(prefix.trim_end_matches('/'))))
            .try_collect()
            .await
            .map_err(err)?;
        Ok(metas
            .into_iter()
            .map(|m| {
                (
                    m.location.to_string(),
                    ObjectInfo {
                        last_modified: to_time(m.last_modified.timestamp()),
                        size: m.size,
                    },
                )
            })
            .collect())
    }
}
