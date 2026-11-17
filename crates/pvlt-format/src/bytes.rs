//! Byte encoding helpers from section 1, written without indexing so nothing here can panic.

use crate::Error;

/// `lp(x) = u16(len(x)) ‖ x`.
pub(crate) fn lp(out: &mut Vec<u8>, x: &[u8]) -> Result<(), Error> {
    let len =
        u16::try_from(x.len()).map_err(|_| Error::Invalid("lp value longer than 65535 bytes"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(x);
    Ok(())
}

/// `tuple(a, b, …) = lp(a) ‖ lp(b) ‖ …`.
pub(crate) fn tuple(parts: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for p in parts {
        lp(&mut out, p)?;
    }
    Ok(out)
}

/// A cursor over a byte slice.
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Reader(b)
    }

    pub(crate) fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(Error::Malformed("input too short"))?;
        self.0 = rest;
        Ok(*head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(u8::from_be_bytes(self.take()?))
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    pub(crate) fn rest(self) -> &'a [u8] {
        self.0
    }
}
