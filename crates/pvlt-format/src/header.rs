//! Section 4: the 104-byte header at the start of every object in the bucket.

use zeroize::Zeroizing;

use crate::bytes::Reader;
use crate::suite::{self, Suite};
use crate::{Error, Id, Key, Salt};

/// Length of the object header.
pub const HEADER_LEN: usize = 104;
/// Length of the part of the header that is the derivation context: magic through `chunk_size`.
pub const HEADER_CTX_LEN: usize = 48;

const MAGIC: [u8; 4] = *b"PVLT";
const VERSION: u8 = 0x01;
const LABEL: &str = "object";

/// What an object holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A fact: one padded value, one AEAD call (section 4.1).
    Fact,
    /// A blob: a chunked stream (section 4.2).
    Blob,
}

impl Kind {
    fn id(self) -> u8 {
        match self {
            Kind::Fact => 0x01,
            Kind::Blob => 0x02,
        }
    }
}

/// A parsed object header. Parsing checks structure only; nothing here is authenticated until the object is
/// opened with its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Fact or blob.
    pub kind: Kind,
    /// The suite the object was sealed with.
    pub suite: Suite,
    /// The domain (tenant).
    pub domain_id: Id,
    /// The random object id, which is also the bucket key.
    pub object_id: Id,
    /// Starts at 0 and increments when a fact is re-encrypted under a new DEK.
    pub dek_generation: u32,
    /// 0 for a fact; plaintext bytes per chunk for a blob.
    pub chunk_size: u32,
    /// The per-object salt.
    pub salt: Salt,
    /// The key commitment.
    pub commitment: [u8; 32],
}

impl Header {
    /// Parses the first 104 bytes of an object.
    pub fn parse(object: &[u8]) -> Result<Self, Error> {
        Ok(Self::split(object)?.0)
    }

    /// Parses the header and returns it with the bytes that follow.
    pub(crate) fn split(object: &[u8]) -> Result<(Self, &[u8]), Error> {
        let mut r = Reader::new(object);
        if r.take::<4>()? != MAGIC {
            return Err(Error::Malformed("bad magic"));
        }
        if r.u8()? != VERSION {
            return Err(Error::Malformed("unknown format version"));
        }
        let kind = match r.u8()? {
            0x01 => Kind::Fact,
            0x02 => Kind::Blob,
            _ => return Err(Error::Malformed("unknown object kind")),
        };
        let suite = Suite::from_id(r.u16()?)?;
        let header = Header {
            kind,
            suite,
            domain_id: r.take()?,
            object_id: r.take()?,
            dek_generation: r.u32()?,
            chunk_size: r.u32()?,
            salt: r.take()?,
            commitment: r.take()?,
        };
        Ok((header, r.rest()))
    }

    /// The first 48 bytes: the derivation context for the object's key.
    pub(crate) fn ctx(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.kind.id());
        out.extend_from_slice(&self.suite.id().to_be_bytes());
        out.extend_from_slice(&self.domain_id);
        out.extend_from_slice(&self.object_id);
        out.extend_from_slice(&self.dek_generation.to_be_bytes());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out
    }

    /// The full 104 bytes, which are also the AEAD associated data.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.ctx();
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.commitment);
        out
    }

    /// Builds the header for a new object: derives the object's AEAD key and fills in the commitment.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal(
        dek: &Key,
        kind: Kind,
        suite: Suite,
        domain_id: &Id,
        object_id: &Id,
        dek_generation: u32,
        chunk_size: u32,
        salt: &Salt,
    ) -> Result<(Self, Zeroizing<Key>), Error> {
        let mut header = Header {
            kind,
            suite,
            domain_id: *domain_id,
            object_id: *object_id,
            dek_generation,
            chunk_size,
            salt: *salt,
            commitment: [0; 32],
        };
        let d = suite::derive(dek, suite, salt, LABEL, &header.ctx())?;
        header.commitment = d.ck;
        Ok((header, d.ek))
    }

    /// Checks the kind and the key commitment, and returns the object's AEAD key. Runs before any decryption.
    pub(crate) fn open(&self, dek: &Key, kind: Kind) -> Result<Zeroizing<Key>, Error> {
        if self.kind != kind {
            return Err(Error::Malformed("wrong object kind"));
        }
        suite::derive_checked(
            dek,
            self.suite,
            &self.salt,
            LABEL,
            &self.ctx(),
            &self.commitment,
        )
    }
}
