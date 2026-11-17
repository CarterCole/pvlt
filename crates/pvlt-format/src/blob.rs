//! Section 4.2: blob objects. A STREAM construction over fixed-size chunks.
//!
//! [`seal`] and [`open`] work on whole buffers. The constant-memory streaming reader and writer (milestone M5)
//! will be built on the same per-chunk nonces and checks.

use zeroize::Zeroizing;

use crate::header::{Header, Kind};
use crate::suite::{self, Suite};
use crate::{Error, Id, Key, Salt, TAG_LEN};

/// Smallest allowed chunk size.
pub const CHUNK_MIN: u32 = 1024;
/// Largest allowed chunk size, 16 MiB.
pub const CHUNK_MAX: u32 = 16 * 1024 * 1024;
/// The default chunk size.
pub const CHUNK_DEFAULT: u32 = 65_536;

/// Padmé: rounds `len` up so that it leaks at most O(log log len) bits. Defined for `len >= 2`.
pub fn padme(len: u64) -> Option<u64> {
    if len < 2 {
        return None;
    }
    let e = len.ilog2();
    let s = e.ilog2() + 1;
    let mask = (1u64 << (e - s)) - 1;
    Some(len.checked_add(mask)? & !mask)
}

fn check_chunk_size(chunk_size: u32) -> Result<usize, Error> {
    if !chunk_size.is_multiple_of(1024) || !(CHUNK_MIN..=CHUNK_MAX).contains(&chunk_size) {
        return Err(Error::Malformed("bad chunk size"));
    }
    usize::try_from(chunk_size).map_err(|_| Error::Malformed("bad chunk size"))
}

/// `P = u64(len(data)) ‖ data ‖ zeros`, padded to the Padmé length.
fn plaintext(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let too_long = Error::Invalid("blob too long");
    let len = u64::try_from(data.len()).map_err(|_| too_long)?;
    let total = padme(len.checked_add(8).ok_or(too_long)?).ok_or(too_long)?;
    let total = usize::try_from(total).map_err(|_| too_long)?;
    let mut p = Zeroizing::new(Vec::with_capacity(total));
    p.extend_from_slice(&len.to_be_bytes());
    p.extend_from_slice(data);
    p.resize(total, 0);
    Ok(p)
}

/// Seals `data` into a blob object: `header ‖ C_0 ‖ … ‖ C_{n-1}`.
///
/// `salt` MUST be 24 fresh random bytes; it must never repeat for the same `dek`.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    dek: &Key,
    suite: Suite,
    domain_id: &Id,
    object_id: &Id,
    dek_generation: u32,
    chunk_size: u32,
    salt: &Salt,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    let cs = check_chunk_size(chunk_size).map_err(|_| Error::Invalid("bad chunk size"))?;
    let p = plaintext(data)?;
    let (header, ek) = Header::seal(
        dek,
        Kind::Blob,
        suite,
        domain_id,
        object_id,
        dek_generation,
        chunk_size,
        salt,
    )?;
    let aad = header.to_bytes();
    let mut object = aad.clone();
    let count = p.chunks(cs).count();
    for (i, chunk) in p.chunks(cs).enumerate() {
        let index = u32::try_from(i).map_err(|_| Error::Invalid("blob has too many chunks"))?;
        let nonce = suite::nonce_chunk(suite, salt, index, i + 1 == count);
        object.extend_from_slice(&suite::seal(suite, &ek, &nonce, chunk, &aad)?);
    }
    Ok(object)
}

/// Opens a blob object and returns the data. Nothing is returned unless every chunk verifies, the stream ends
/// with a chunk sealed as final, and the padding is canonical.
pub fn open(dek: &Key, object: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (header, body) = Header::split(object)?;
    let ek = header.open(dek, Kind::Blob)?;
    let cs = check_chunk_size(header.chunk_size)?;
    let aad = header.to_bytes();

    let count = body.chunks(cs + TAG_LEN).count();
    if count == 0 {
        return Err(Error::OpenFailed);
    }
    let mut p = Zeroizing::new(Vec::with_capacity(body.len()));
    for (i, chunk) in body.chunks(cs + TAG_LEN).enumerate() {
        let last = i + 1 == count;
        // `chunks` makes every chunk but the last full-sized. A final chunk must carry at least one byte.
        if last && chunk.len() <= TAG_LEN {
            return Err(Error::OpenFailed);
        }
        let index = u32::try_from(i).map_err(|_| Error::OpenFailed)?;
        let nonce = suite::nonce_chunk(header.suite, &header.salt, index, last);
        p.extend_from_slice(&suite::open(header.suite, &ek, &nonce, chunk, &aad)?);
    }

    let (len_bytes, rest) = p.split_first_chunk::<8>().ok_or(Error::OpenFailed)?;
    let declared = u64::from_be_bytes(*len_bytes);
    let total = u64::try_from(p.len()).map_err(|_| Error::OpenFailed)?;
    if declared.checked_add(8).and_then(padme) != Some(total) {
        return Err(Error::OpenFailed);
    }
    let declared = usize::try_from(declared).map_err(|_| Error::OpenFailed)?;
    let (data, padding) = rest.split_at_checked(declared).ok_or(Error::OpenFailed)?;
    if padding.iter().any(|b| *b != 0) {
        return Err(Error::OpenFailed);
    }
    Ok(Zeroizing::new(data.to_vec()))
}

/// The public fields of a blob object's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobHeader {
    /// The suite the chunks are sealed with.
    pub suite: Suite,
    /// The domain.
    pub domain_id: Id,
    /// The object.
    pub object_id: Id,
    /// The key generation.
    pub dek_generation: u32,
    /// Plaintext bytes per chunk.
    pub chunk_size: u32,
}

/// Parses a blob object's 104-byte header and checks its key commitment under `dek`, without decrypting
/// anything. This is how the vault checks an upload it cannot read: the header proves the client used the key it
/// was given, for this domain, object and generation.
pub fn check_header(dek: &Key, header_bytes: &[u8]) -> Result<BlobHeader, Error> {
    let bytes = header_bytes
        .get(..crate::header::HEADER_LEN)
        .ok_or(Error::Malformed("object is shorter than its header"))?;
    let header = Header::parse(bytes)?;
    header.open(dek, Kind::Blob)?;
    check_chunk_size(header.chunk_size)?;
    Ok(BlobHeader {
        suite: header.suite,
        domain_id: header.domain_id,
        object_id: header.object_id,
        dek_generation: header.dek_generation,
        chunk_size: header.chunk_size,
    })
}

// --- Streaming ------------------------------------------------------------------------------------------------

/// Seals a blob a piece at a time, in constant memory.
///
/// The output is **byte for byte** what [`seal`] produces for the same inputs; the tests check that for many
/// splits of the input. The writer needs the data length up front, because the stream starts with it and its
/// padding depends on it.
///
/// ```text
/// let (mut w, header) = BlobWriter::new(&dek, suite, &domain, &object, 0, 65536, &salt, data_len)?;
/// out.write(&header);
/// for piece in data { out.write(&w.write(piece)?); }
/// out.write(&w.finish()?);
/// ```
pub struct BlobWriter {
    suite: Suite,
    ek: Zeroizing<Key>,
    aad: Vec<u8>,
    salt: Salt,
    chunk_size: usize,
    /// Total length of `P`, known from the start.
    total: u64,
    /// How much of `P` has been sealed into emitted chunks.
    sealed: u64,
    data_len: u64,
    data_written: u64,
    index: u32,
    buf: Zeroizing<Vec<u8>>,
}

impl BlobWriter {
    /// Starts a blob. Returns the writer and the 104-byte header to write first.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dek: &Key,
        suite: Suite,
        domain_id: &Id,
        object_id: &Id,
        dek_generation: u32,
        chunk_size: u32,
        salt: &Salt,
        data_len: u64,
    ) -> Result<(Self, Vec<u8>), Error> {
        let cs = check_chunk_size(chunk_size).map_err(|_| Error::Invalid("bad chunk size"))?;
        let too_long = Error::Invalid("blob too long");
        let total = padme(data_len.checked_add(8).ok_or(too_long)?).ok_or(too_long)?;
        let (header, ek) = Header::seal(
            dek,
            Kind::Blob,
            suite,
            domain_id,
            object_id,
            dek_generation,
            chunk_size,
            salt,
        )?;
        let aad = header.to_bytes();
        let mut buf = Zeroizing::new(Vec::with_capacity(cs + 1));
        buf.extend_from_slice(&data_len.to_be_bytes());
        Ok((
            Self {
                suite,
                ek,
                aad: aad.clone(),
                salt: *salt,
                chunk_size: cs,
                total,
                sealed: 0,
                data_len,
                data_written: 0,
                index: 0,
                buf,
            },
            aad,
        ))
    }

    fn seal_chunk(&mut self, last: bool) -> Result<Vec<u8>, Error> {
        let take = self.buf.len().min(self.chunk_size);
        let nonce = suite::nonce_chunk(self.suite, &self.salt, self.index, last);
        let plain = self
            .buf
            .get(..take)
            .ok_or(Error::Invalid("internal: chunk longer than the buffer"))?;
        let chunk = suite::seal(self.suite, &self.ek, &nonce, plain, &self.aad)?;
        self.sealed += u64::try_from(take).map_err(|_| Error::Invalid("blob too long"))?;
        self.index = self
            .index
            .checked_add(1)
            .ok_or(Error::Invalid("blob has too many chunks"))?;
        self.buf.drain(..take);
        Ok(chunk)
    }

    /// Takes the next piece of data and returns any chunks that are now complete (possibly none). A chunk is
    /// held back until more of the stream is known to follow, because the last chunk is sealed differently.
    pub fn write(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let n = u64::try_from(data.len()).map_err(|_| Error::Invalid("blob too long"))?;
        if self
            .data_written
            .checked_add(n)
            .is_none_or(|w| w > self.data_len)
        {
            return Err(Error::Invalid("more data than was declared"));
        }
        self.data_written += n;
        let mut out = Vec::new();
        let mut rest = data;
        while !rest.is_empty() {
            let room = (self.chunk_size + 1).saturating_sub(self.buf.len()).max(1);
            let (now, later) = rest.split_at(rest.len().min(room));
            self.buf.extend_from_slice(now);
            rest = later;
            // A full chunk is final only if it ends the stream; more of `P` follows while `sealed + chunk <
            // total`. Padding always follows data unless the data fills `P` exactly.
            while self.buf.len() > self.chunk_size
                || (self.buf.len() == self.chunk_size
                    && self.sealed + u64::try_from(self.chunk_size).unwrap_or(u64::MAX)
                        < self.total)
            {
                out.extend_from_slice(&self.seal_chunk(false)?);
            }
        }
        Ok(out)
    }

    /// Adds the padding and seals the rest as the final chunk. Fails if less data was written than declared.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        if self.data_written != self.data_len {
            return Err(Error::Invalid("less data than was declared"));
        }
        let pending = u64::try_from(self.buf.len()).map_err(|_| Error::Invalid("blob too long"))?;
        let missing = self
            .total
            .checked_sub(self.sealed + pending)
            .ok_or(Error::Invalid("blob too long"))?;
        let missing = usize::try_from(missing).map_err(|_| Error::Invalid("blob too long"))?;
        let new_len = self.buf.len() + missing;
        self.buf.resize(new_len, 0);
        let mut out = Vec::new();
        while self.buf.len() > self.chunk_size {
            out.extend_from_slice(&self.seal_chunk(false)?);
        }
        out.extend_from_slice(&self.seal_chunk(true)?);
        Ok(out)
    }
}

/// Opens a blob a piece at a time, in constant memory: one chunk of ciphertext and one of plaintext at a time.
///
/// Plaintext is returned as soon as the chunk it is in has verified, so **the caller must throw away everything
/// it received if [`BlobReader::push`] or [`BlobReader::finish`] fails** (the format allows releasing verified
/// chunks of an object that later fails; it does not allow trusting them). The length, the final chunk and the
/// padding are only checked by `finish`, so a stream is not good until `finish` has returned `Ok`.
pub struct BlobReader {
    suite: Suite,
    ek: Zeroizing<Key>,
    aad: Vec<u8>,
    salt: Salt,
    chunk_size: usize,
    index: u32,
    buf: Vec<u8>,
    /// The data length declared in the first chunk.
    declared: Option<u64>,
    /// How much of `P` has been opened.
    opened: u64,
    /// How many data bytes have been returned.
    returned: u64,
}

impl BlobReader {
    /// Starts reading with the object's 104-byte header and its DEK. Checks the key commitment before anything
    /// is decrypted.
    pub fn new(dek: &Key, header_bytes: &[u8]) -> Result<Self, Error> {
        let header_bytes = header_bytes
            .get(..crate::header::HEADER_LEN)
            .ok_or(Error::Malformed("object is shorter than its header"))?;
        let header = Header::parse(header_bytes)?;
        let ek = header.open(dek, Kind::Blob)?;
        let cs = check_chunk_size(header.chunk_size)?;
        Ok(Self {
            suite: header.suite,
            ek,
            aad: header.to_bytes(),
            salt: header.salt,
            chunk_size: cs,
            index: 0,
            buf: Vec::new(),
            declared: None,
            opened: 0,
            returned: 0,
        })
    }

    /// The chunk size from the header, so a caller knows how much to read at a time.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Feeds ciphertext (the bytes after the header) and returns the plaintext of every chunk that is now known
    /// not to be the last and has verified.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.buf.extend_from_slice(bytes);
        let mut out = Zeroizing::new(Vec::new());
        let sealed = self.chunk_size + TAG_LEN;
        // More than one chunk's worth is buffered, so the first is not the last.
        while self.buf.len() > sealed {
            let chunk: Vec<u8> = self.buf.drain(..sealed).collect();
            self.open_chunk(&chunk, false, &mut out)?;
        }
        Ok(out)
    }

    /// Opens the final chunk and checks the length and the padding. Returns the last of the data.
    pub fn finish(mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.buf.len() <= TAG_LEN {
            return Err(Error::OpenFailed);
        }
        let chunk = core::mem::take(&mut self.buf);
        let mut out = Zeroizing::new(Vec::new());
        self.open_chunk(&chunk, true, &mut out)?;
        let declared = self.declared.ok_or(Error::OpenFailed)?;
        if declared.checked_add(8).and_then(padme) != Some(self.opened) || self.returned != declared
        {
            return Err(Error::OpenFailed);
        }
        Ok(out)
    }

    fn open_chunk(
        &mut self,
        chunk: &[u8],
        last: bool,
        out: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), Error> {
        let nonce = suite::nonce_chunk(self.suite, &self.salt, self.index, last);
        let p = suite::open(self.suite, &self.ek, &nonce, chunk, &self.aad)?;
        self.index = self.index.checked_add(1).ok_or(Error::OpenFailed)?;
        let mut p: &[u8] = &p;
        if self.declared.is_none() {
            let (len, rest) = p.split_first_chunk::<8>().ok_or(Error::OpenFailed)?;
            self.declared = Some(u64::from_be_bytes(*len));
            self.opened += 8;
            p = rest;
        }
        let declared = self.declared.ok_or(Error::OpenFailed)?;
        let room = declared - self.returned;
        let take = usize::try_from(room).unwrap_or(usize::MAX).min(p.len());
        let (data, padding) = p.split_at(take);
        if padding.iter().any(|b| *b != 0) {
            return Err(Error::OpenFailed);
        }
        out.extend_from_slice(data);
        self.returned += u64::try_from(take).map_err(|_| Error::OpenFailed)?;
        self.opened += u64::try_from(p.len()).map_err(|_| Error::OpenFailed)?;
        Ok(())
    }
}

/// How long a sealed blob object is for `data_len` bytes of data: header plus chunks plus tags. Used to check
/// an uploaded object's size without opening it.
pub fn sealed_len(data_len: u64, chunk_size: u32) -> Option<u64> {
    let cs = u64::from(chunk_size);
    if check_chunk_size(chunk_size).is_err() {
        return None;
    }
    let total = padme(data_len.checked_add(8)?)?;
    let chunks = total.div_ceil(cs);
    Some(
        u64::try_from(crate::header::HEADER_LEN).ok()?
            + total
            + chunks * u64::try_from(TAG_LEN).ok()?,
    )
}

/// Whether `object_len` is a possible length for a blob object with this chunk size: a header, then whole
/// chunks and a final chunk of 1 to `chunk_size` bytes, each with a tag, **and** a plaintext length that padmé
/// could produce. This is the most that can be said about an object without its key.
pub fn plausible_len(object_len: u64, chunk_size: u32) -> bool {
    let Some(body) =
        object_len.checked_sub(u64::try_from(crate::header::HEADER_LEN).unwrap_or(u64::MAX))
    else {
        return false;
    };
    let cs = u64::from(chunk_size);
    if check_chunk_size(chunk_size).is_err() {
        return false;
    }
    let sealed = cs + u64::try_from(TAG_LEN).unwrap_or(16);
    let full = body / sealed;
    let rest = body % sealed;
    // The remainder is the final chunk, which must hold at least one byte; no remainder means the last full
    // chunk was the final one.
    let (chunks, last_plain) = if rest == 0 {
        if full == 0 {
            return false;
        }
        (full, cs)
    } else if rest > u64::try_from(TAG_LEN).unwrap_or(16) {
        (full + 1, rest - u64::try_from(TAG_LEN).unwrap_or(16))
    } else {
        return false;
    };
    let total = (chunks - 1) * cs + last_plain;
    // `total` must be a padmé length of some data length `d` with `total >= 8 + d`.
    total >= 8 && padme(total) == Some(total)
}
