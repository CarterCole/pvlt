//! The object store: where sealed fact values live (PLAN.md 3.7, FORMAT.md section 7).
//!
//! Everything in a bucket is ciphertext under a random id, so the bucket reveals nothing the key store does not
//! already, and an implementation never needs a key. The trait is the seam the engine is tested through; the
//! real implementation is in `pvlt_server::bucket`, and [`crate::memory::MemObjectStore`] is the in-process one.

use core::fmt;
use core::future::Future;
use core::time::Duration;

use pvlt_format::Id;
use time::OffsetDateTime;

/// Where an object lives: a domain and the random object id from its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectKey {
    /// The domain.
    pub domain_id: Id,
    /// The object's random id.
    pub object_id: Id,
}

impl ObjectKey {
    /// The key in the bucket: `v1/<hex(domain_id)>/<hex(object_id)[0..2]>/<hex(object_id)>` (FORMAT.md
    /// section 7). Nothing else about the object appears in it.
    pub fn path(&self) -> String {
        let object = hex::encode(self.object_id);
        format!(
            "v1/{}/{}/{object}",
            hex::encode(self.domain_id),
            object.get(..2).unwrap_or("00")
        )
    }

    /// Where a client uploads a blob's object before the vault has checked it. The vault copies it to
    /// [`ObjectKey::path`] on completion, so an upload address handed to a client can never write the object a
    /// reader is given. The id is derived from this key's object id, so it needs no row of its own, and no fact
    /// holds a key for it: the sweeper removes a staging object once it is older than its grace period.
    pub fn staging(&self) -> ObjectKey {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::new()
            .chain_update(pvlt_format::PREFIX)
            .chain_update(b"upload-staging\0")
            .chain_update(self.domain_id)
            .chain_update(self.object_id)
            .finalize()
            .into();
        let mut object_id = [0u8; 16];
        object_id.copy_from_slice(digest.get(..16).unwrap_or(&[0; 16]));
        ObjectKey {
            domain_id: self.domain_id,
            object_id,
        }
    }

    /// The prefix that holds every object of a domain.
    pub fn domain_prefix(domain_id: &Id) -> String {
        format!("v1/{}/", hex::encode(domain_id))
    }

    /// Reads a key back from a bucket path, or `None` if the path is not one this layout makes.
    pub fn from_path(path: &str) -> Option<Self> {
        let rest = path.strip_prefix("v1/")?;
        let mut parts = rest.split('/');
        let (domain, shard, object) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || object.get(..2) != Some(shard) {
            return None;
        }
        let key = Self {
            domain_id: hex::decode(domain).ok()?.try_into().ok()?,
            object_id: hex::decode(object).ok()?.try_into().ok()?,
        };
        (key.path() == path).then_some(key)
    }
}

/// What a listing says about an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectMeta {
    /// The object.
    pub key: ObjectKey,
    /// When it was last written, by the store's clock.
    pub last_modified: OffsetDateTime,
    /// Its size in bytes.
    pub size: u64,
}

/// Why an object-store call failed. The text comes from the driver and never holds object contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectError(pub String);

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "object store failure: {}", self.0)
    }
}

impl std::error::Error for ObjectError {}

/// A bucket of sealed objects, and of the signed logs kept beside them.
///
/// Objects are addressed by [`ObjectKey`]; the log files (FORMAT.md section 7, `ledger/` and `checkpoints/`)
/// by path. The path methods exist so the ledger can live in a separate bucket that is never rolled back: see
/// [`SplitStore`].
pub trait ObjectStore: Send + Sync {
    /// Checks that the bucket is reachable. Never writes.
    fn ping(&self) -> impl Future<Output = Result<(), ObjectError>> + Send;

    /// Writes a file at a path. Writing the same path twice replaces it.
    fn put_path(
        &self,
        path: &str,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<(), ObjectError>> + Send;

    /// Reads a file, or `None` if there is none.
    fn get_path(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, ObjectError>> + Send;

    /// Deletes a file. Deleting one that is not there is not an error.
    fn delete_path(&self, path: &str) -> impl Future<Output = Result<(), ObjectError>> + Send;

    /// Lists the paths and sizes under a prefix, with their write times, in no particular order.
    fn list_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<(String, ObjectInfo)>, ObjectError>> + Send;

    /// The size of a file in bytes, or `None` if there is none. Does not read it.
    fn head_path(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<Option<u64>, ObjectError>> + Send {
        async move {
            Ok(self
                .get_path(path)
                .await?
                .map(|b| u64::try_from(b.len()).unwrap_or(u64::MAX)))
        }
    }

    /// Up to `len` bytes of a file starting at `start`, or `None` if there is no such file. A range that runs
    /// past the end returns what is there. The default reads the whole file; real stores override it.
    fn get_range(
        &self,
        path: &str,
        start: u64,
        len: u64,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, ObjectError>> + Send {
        async move {
            Ok(self.get_path(path).await?.map(|b| {
                let from = usize::try_from(start).unwrap_or(usize::MAX).min(b.len());
                let to = usize::try_from(start.saturating_add(len))
                    .unwrap_or(usize::MAX)
                    .min(b.len());
                b.get(from..to).unwrap_or_default().to_vec()
            }))
        }
    }

    /// Copies a file to another path, replacing what is there. [`ObjectError`] if `from` does not exist. The
    /// default reads and writes the whole file; real stores override it with a server-side copy.
    fn copy_path(
        &self,
        from: &str,
        to: &str,
    ) -> impl Future<Output = Result<(), ObjectError>> + Send {
        async move {
            let bytes = self
                .get_path(from)
                .await?
                .ok_or_else(|| ObjectError("the file to copy does not exist".to_owned()))?;
            self.put_path(to, bytes).await
        }
    }

    /// A URL a client can `PUT` the object to without credentials, valid for `ttl`, or `None` if this store
    /// cannot make one (a local directory, memory). Then the vault proxies the upload.
    fn presign_put(
        &self,
        _path: &str,
        _ttl: Duration,
    ) -> impl Future<Output = Result<Option<String>, ObjectError>> + Send {
        async { Ok(None) }
    }

    /// A URL a client can `GET` the object from without credentials, valid for `ttl`, or `None`.
    fn presign_get(
        &self,
        _path: &str,
        _ttl: Duration,
    ) -> impl Future<Output = Result<Option<String>, ObjectError>> + Send {
        async { Ok(None) }
    }

    /// Writes an object.
    fn put(
        &self,
        key: &ObjectKey,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<(), ObjectError>> + Send {
        async move { self.put_path(&key.path(), bytes).await }
    }

    /// Reads an object, or `None` if there is none.
    fn get(
        &self,
        key: &ObjectKey,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, ObjectError>> + Send {
        async move { self.get_path(&key.path()).await }
    }

    /// Deletes an object. Deleting one that is not there is not an error.
    fn delete(&self, key: &ObjectKey) -> impl Future<Output = Result<(), ObjectError>> + Send {
        async move { self.delete_path(&key.path()).await }
    }

    /// Lists every object of a domain, in no particular order. Anything under the prefix that the layout did not
    /// write is left out, so it is never reported and never swept.
    fn list(
        &self,
        domain_id: &Id,
    ) -> impl Future<Output = Result<Vec<ObjectMeta>, ObjectError>> + Send {
        async move {
            Ok(self
                .list_prefix(&ObjectKey::domain_prefix(domain_id))
                .await?
                .into_iter()
                .filter_map(|(path, info)| {
                    let key = ObjectKey::from_path(&path)?;
                    (key.domain_id == *domain_id).then_some(ObjectMeta {
                        key,
                        last_modified: info.last_modified,
                        size: info.size,
                    })
                })
                .collect())
        }
    }
}

/// What a prefix listing says about a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectInfo {
    /// When it was last written, by the store's clock.
    pub last_modified: OffsetDateTime,
    /// Its size in bytes.
    pub size: u64,
}

/// Two buckets behind one [`ObjectStore`]: sealed objects go to `data`, and everything under `ledger/` and
/// `checkpoints/` goes to `logs`. Make `logs` a bucket that is never restored from a backup, with versioning or
/// object lock if you have it, and a shred survives losing the data bucket's history. (PLAN.md 3.3.)
#[derive(Debug, Clone)]
pub struct SplitStore<D, L> {
    /// Sealed objects.
    pub data: D,
    /// Ledger and checkpoint files.
    pub logs: L,
}

fn is_log_path(path: &str) -> bool {
    path.starts_with("ledger/") || path.starts_with("checkpoints/")
}

impl<D: ObjectStore, L: ObjectStore> ObjectStore for SplitStore<D, L> {
    async fn ping(&self) -> Result<(), ObjectError> {
        self.data.ping().await?;
        self.logs.ping().await
    }

    async fn put_path(&self, path: &str, bytes: Vec<u8>) -> Result<(), ObjectError> {
        if is_log_path(path) {
            self.logs.put_path(path, bytes).await
        } else {
            self.data.put_path(path, bytes).await
        }
    }

    async fn get_path(&self, path: &str) -> Result<Option<Vec<u8>>, ObjectError> {
        if is_log_path(path) {
            self.logs.get_path(path).await
        } else {
            self.data.get_path(path).await
        }
    }

    async fn delete_path(&self, path: &str) -> Result<(), ObjectError> {
        if is_log_path(path) {
            self.logs.delete_path(path).await
        } else {
            self.data.delete_path(path).await
        }
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, ObjectInfo)>, ObjectError> {
        if is_log_path(prefix) {
            self.logs.list_prefix(prefix).await
        } else {
            self.data.list_prefix(prefix).await
        }
    }

    async fn head_path(&self, path: &str) -> Result<Option<u64>, ObjectError> {
        if is_log_path(path) {
            self.logs.head_path(path).await
        } else {
            self.data.head_path(path).await
        }
    }

    async fn get_range(
        &self,
        path: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<Vec<u8>>, ObjectError> {
        if is_log_path(path) {
            self.logs.get_range(path, start, len).await
        } else {
            self.data.get_range(path, start, len).await
        }
    }

    async fn copy_path(&self, from: &str, to: &str) -> Result<(), ObjectError> {
        match (is_log_path(from), is_log_path(to)) {
            (false, false) => self.data.copy_path(from, to).await,
            (true, true) => self.logs.copy_path(from, to).await,
            _ => Err(ObjectError(
                "cannot copy between the data and log buckets".to_owned(),
            )),
        }
    }

    async fn presign_put(&self, path: &str, ttl: Duration) -> Result<Option<String>, ObjectError> {
        if is_log_path(path) {
            Ok(None)
        } else {
            self.data.presign_put(path, ttl).await
        }
    }

    async fn presign_get(&self, path: &str, ttl: Duration) -> Result<Option<String>, ObjectError> {
        if is_log_path(path) {
            Ok(None)
        } else {
            self.data.presign_get(path, ttl).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_round_trips_through_its_path() {
        let key = ObjectKey {
            domain_id: [0xab; 16],
            object_id: [0x01; 16],
        };
        let path = key.path();
        assert_eq!(
            path,
            "v1/abababababababababababababababab/01/01010101010101010101010101010101"
        );
        assert_eq!(ObjectKey::from_path(&path), Some(key));
        // The staging key is an ordinary object key of the same domain, different from the object's own.
        let staging = key.staging();
        assert_eq!(staging.domain_id, key.domain_id);
        assert_ne!(staging.object_id, key.object_id);
        assert_eq!(ObjectKey::from_path(&staging.path()), Some(staging));
        assert_eq!(staging, key.staging());
    }

    #[test]
    fn paths_that_are_not_ours_are_refused() {
        for bad in [
            "",
            "v1/",
            "v2/abababababababababababababababab/01/01010101010101010101010101010101",
            // Wrong shard.
            "v1/abababababababababababababababab/02/01010101010101010101010101010101",
            // Upper case is not what the layout writes.
            "v1/ABABABABABABABABABABABABABABABAB/01/01010101010101010101010101010101",
            // Extra component.
            "v1/abababababababababababababababab/01/01010101010101010101010101010101/x",
            "ledger/abababababababababababababababab/00000000000000000000.json",
        ] {
            assert_eq!(ObjectKey::from_path(bad), None, "{bad}");
        }
    }
}
