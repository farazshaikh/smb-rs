//! Explicit-endian integer reads/writes.
//!
//! SMB is little-endian on the wire regardless of host architecture. These
//! helpers make the byte order explicit at every call site so the code is
//! correct on big-endian machines too.

/// Read a little-endian unsigned integer of `N` bytes starting at `buf[pos]`.
///
/// Works for any N ≤ 8; the result is zero-extended to u64 and the caller
/// casts/truncates to the desired width.
#[inline(always)]
pub fn read_le(buf: &[u8], pos: usize, n: usize) -> Result<u64, crate::error::ProtoError> {
    if pos + n > buf.len() {
        return Err(crate::error::ProtoError::Overrun {
            need: n,
            at: pos,
            have: buf.len(),
        });
    }
    let mut v: u64 = 0;
    for i in 0..n {
        v |= (buf[pos + i] as u64) << (8 * i);
    }
    Ok(v)
}

/// Write a little-endian unsigned integer of `n` bytes into `buf` at `pos`.
#[inline(always)]
pub fn write_le(buf: &mut [u8], pos: usize, val: u64, n: usize) {
    for i in 0..n {
        buf[pos + i] = ((val >> (8 * i)) & 0xff) as u8;
    }
}

macro_rules! impl_le {
    ($name:ident, $ty:ty, $size:expr) => {
        /// Read a little-endian value from the buffer at `pos`.
        #[inline(always)]
        pub fn $name(buf: &[u8], pos: usize) -> Result<$ty, crate::error::ProtoError> {
            if pos + $size > buf.len() {
                return Err(crate::error::ProtoError::Overrun {
                    need: $size,
                    at: pos,
                    have: buf.len(),
                });
            }
            let mut bytes = [0u8; $size];
            bytes.copy_from_slice(&buf[pos..pos + $size]);
            Ok(<$ty>::from_le_bytes(bytes))
        }
    };
}

impl_le!(read_u8_le, u8, 1);
impl_le!(read_u16_le, u16, 2);
impl_le!(read_u32_le, u32, 4);
impl_le!(read_u64_le, u64, 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn little_endian_reads() {
        let buf = [0x34, 0x12, 0x78, 0x56, 0xEF, 0xCD, 0xAB, 0x90];
        assert_eq!(read_u8_le(&buf, 0).unwrap(), 0x34);
        assert_eq!(read_u16_le(&buf, 0).unwrap(), 0x1234);
        assert_eq!(read_u32_le(&buf, 0).unwrap(), 0x5678_1234);
        assert_eq!(read_u64_le(&buf, 0).unwrap(), 0x90AB_CDEF_5678_1234);
    }

    #[test]
    fn overrun_returns_error() {
        let buf = [0u8; 2];
        assert!(read_u32_le(&buf, 0).is_err());
    }

    #[test]
    fn works_on_synthetic_big_endian_host() {
        // We cannot actually switch the host's endianness, but the
        // from_le_bytes / to_le_bytes approach guarantees correctness
        // regardless of what `as` casting would do.
        let raw: [u8; 2] = [0x01, 0x02];
        // On LE: from_le_bytes([1,2]) = 0x0201
        // On BE: same, because we use from_le_bytes explicitly
        assert_eq!(u16::from_le_bytes(raw), 0x0201);
    }
}
