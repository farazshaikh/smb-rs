//! Cursor-style buffer reader/writer implementing SMB string and alignment
//! rules ([MS-CIFS] §2.2.1.1.1 string formats, [MS-SMB] §2.2.2 extensions).
//!
//! All offsets handed to these helpers are *absolute frame offsets* — the
//! caller adds the buffer's base once; the cursor tracks its own position
//! internally.

/// Reading cursor over a received buffer.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// New reader positioned at `pos` within `buf`.
    pub fn new(buf: &'a [u8], pos: usize) -> Self {
        Reader { buf, pos }
    }

    /// Bytes remaining.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Current position relative to the start of `buf`.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// True when the cursor reached the end of the buffer.
    pub fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Read one unsigned little-endian integer of the given width.
    pub fn uint<const N: usize>(&mut self) -> Result<u64, crate::error::ProtoError> {
        if self.pos + N > self.buf.len() {
            return Err(crate::error::ProtoError::Overrun {
                need: N,
                at: self.pos,
                have: self.buf.len(),
            });
        }
        let mut v: u64 = 0;
        for i in 0..N {
            v |= (self.buf[self.pos + i] as u64) << (8 * i);
        }
        self.pos += N;
        Ok(v)
    }

    /// Read a single byte.
    pub fn u8v(&mut self) -> Result<u8, crate::error::ProtoError> {
        if self.pos >= self.buf.len() {
            return Err(crate::error::ProtoError::Overrun {
                need: 1,
                at: self.pos,
                have: self.buf.len(),
            });
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Skip forward by `n` bytes (clamped to the end).
    pub fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());
    }

    /// Borrow the next `n` bytes without copying.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], crate::error::ProtoError> {
        if self.pos + n > self.buf.len() {
            return Err(crate::error::ProtoError::Overrun {
                need: n,
                at: self.pos,
                have: self.buf.len(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read a NUL-terminated string honouring the SMB Unicode rules:
    /// when `unicode` is set the cursor first skips one pad byte if the
    /// current position is odd relative to `base`, then decodes UTF-16LE up
    /// to and including the 16-bit terminator.
    ///
    /// `base` must be the absolute frame offset of `buf[0]`.
    pub fn zstring(&mut self, unicode: bool, base: usize) -> String {
        if unicode {
            if (base + self.pos) & 1 != 0 && !self.at_end() {
                self.pos += 1;
            }
            let mut units = Vec::new();
            while self.pos + 1 < self.buf.len() {
                let lo = self.buf[self.pos];
                let hi = self.buf[self.pos + 1];
                self.pos += 2;
                let u = lo as u16 | ((hi as u16) << 8);
                if u == 0 {
                    break;
                }
                units.push(u);
            }
            String::from_utf16_lossy(&units)
        } else {
            let start = self.pos;
            while self.pos < self.buf.len() && self.buf[self.pos] != 0 {
                self.pos += 1;
            }
            let s = String::from_utf8_lossy(&self.buf[start..self.pos]).into_owned();
            if self.pos < self.buf.len() {
                self.pos += 1; // consume terminator
            }
            s
        }
    }

    /// Read exactly `len` bytes as a lossy UTF-16LE or OEM string
    /// (no terminator handling) — used for length-prefixed name fields.
    pub fn fixed_string(&mut self, len: usize, unicode: bool) -> String {
        let end = (self.pos + len).min(self.buf.len());
        let raw = &self.buf[self.pos..end];
        self.pos = end;
        if unicode {
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| c[0] as u16 | ((c[1] as u16) << 8))
                .take_while(|&u| u != 0)
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(raw.split(|&b| b == 0).next().unwrap_or(&[])).into_owned()
        }
    }
}

/// Writing cursor building an outgoing buffer.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
    /// Absolute frame offset that will correspond to `buf[0]` on the wire.
    base: usize,
}

impl Writer {
    /// New writer whose first byte will sit at absolute frame offset `base`
    /// (needed for Unicode parity padding decisions).
    pub fn new(base: usize) -> Self {
        Writer { buf: Vec::new(), base }
    }

    /// Number of bytes written so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True when nothing has been written yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Borrow the accumulated bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    /// Append raw bytes.
    pub fn raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Append one byte.
    pub fn push(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Append a little-endian `u16`.
    pub fn push_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a little-endian `u32`.
    pub fn push_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a little-endian `u64`.
    pub fn push_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Insert a pad byte so the current position becomes even relative to
    /// [`Self::base`] (Unicode alignment requirement).
    pub fn pad_to_parity(&mut self) {
        if (self.base + self.buf.len()) & 1 != 0 {
            self.buf.push(0);
        }
    }

    /// Append a NUL-terminated string honouring the Unicode flag.
    pub fn zstring(&mut self, s: &str, unicode: bool) {
        if unicode {
            self.pad_to_parity();
            for unit in s.encode_utf16() {
                self.buf.extend_from_slice(&unit.to_le_bytes());
            }
            self.buf.extend_from_slice(&[0, 0]);
        } else {
            self.buf.extend_from_slice(s.as_bytes());
            self.buf.push(0);
        }
    }
}
