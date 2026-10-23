//! Lettore minimale del formato wire di Protocol Buffers.
//!
//! Supporta solo ciò che serve agli import; i campi sconosciuti vengono saltati.

use crate::ImportError;

/// Valore di un campo.
pub(crate) enum Value<'a> {
    /// Wire type 0.
    Varint(u64),
    /// Wire type 2.
    Bytes(&'a [u8]),
    /// Wire type 1 e 5: ignorati da tutti i formati supportati.
    Fixed,
}

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ImportError> {
        let (head, tail) = self
            .buf
            .split_at_checked(n)
            .ok_or(ImportError::InvalidFormat)?;
        self.buf = tail;
        Ok(head)
    }

    fn varint(&mut self) -> Result<u64, ImportError> {
        let mut value: u64 = 0;
        for i in 0..10u32 {
            let [byte] = self
                .take(1)?
                .try_into()
                .map_err(|_| ImportError::InvalidFormat)?;
            let part = u64::from(byte & 0x7f);
            // Il decimo byte può contribuire solo con il bit più alto.
            if i == 9 && part > 1 {
                return Err(ImportError::InvalidFormat);
            }
            value |= part << (7 * i);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ImportError::InvalidFormat)
    }

    /// Prossimo campo `(numero, valore)`, o `None` a fine input.
    pub(crate) fn next_field(&mut self) -> Result<Option<(u32, Value<'a>)>, ImportError> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = u32::try_from(key >> 3).map_err(|_| ImportError::InvalidFormat)?;
        if field == 0 {
            return Err(ImportError::InvalidFormat);
        }
        let value = match key & 0x7 {
            0 => Value::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Fixed
            }
            2 => {
                let len =
                    usize::try_from(self.varint()?).map_err(|_| ImportError::InvalidFormat)?;
                Value::Bytes(self.take(len)?)
            }
            5 => {
                self.take(4)?;
                Value::Fixed
            }
            // Gruppi (3, 4) e tipi sconosciuti non sono usati dai formati supportati.
            _ => return Err(ImportError::InvalidFormat),
        };
        Ok(Some((field, value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        let mut r = Reader::new(&[0x08, 0x96, 0x01]);
        let Some((1, Value::Varint(150))) = r.next_field().unwrap() else {
            panic!()
        };
        assert!(r.next_field().unwrap().is_none());

        let max = [
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        ];
        let Some((1, Value::Varint(u64::MAX))) = Reader::new(&max).next_field().unwrap() else {
            panic!()
        };
        let overflow = [
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
        ];
        assert!(Reader::new(&overflow).next_field().is_err());
    }

    #[test]
    fn truncated_input() {
        assert!(Reader::new(&[0x0a, 0x05, 0x01]).next_field().is_err());
        assert!(Reader::new(&[0x08]).next_field().is_err());
        assert!(Reader::new(&[0x08, 0x80]).next_field().is_err());
    }
}
