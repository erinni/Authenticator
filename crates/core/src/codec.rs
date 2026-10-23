//! Lettura di formati binari con controllo dei limiti (nessuna indicizzazione diretta).
//!
//! Ogni lettura oltre la fine dell'input restituisce [`Error::InvalidFormat`].

use crate::error::{Error, Result};

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Byte letti finora.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    /// `true` se tutto l'input è stato consumato.
    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::InvalidFormat)?;
        let out = self.buf.get(self.pos..end).ok_or(Error::InvalidFormat)?;
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::InvalidFormat)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn string(&mut self) -> Result<String> {
        let len = usize::from(self.u16()?);
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidFormat)
    }
}
