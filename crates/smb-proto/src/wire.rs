//! Codec trait and per-frame decode/encode context.
//!
//! SMB field layouts are context-dependent: Unicode string parity is computed
//! against the field's absolute offset from the start of the SMB header, and
//! SMB2 offsets are relative to the 64-byte header. The codec context carries
//! that information so structures can be decoded without threading offsets
//! through every call site.

/// Context used while decoding one frame.
#[derive(Debug, Clone, Copy)]
pub struct DecodeCtx {
    /// Absolute frame offset of the buffer being decoded (usually the offset
    /// of the SMB header, i.e. 4 when an NBSS header precedes it).
    pub base: usize,
    /// Strings are UTF-16LE when set, otherwise OEM/ASCII.
    pub unicode: bool,
}

impl DecodeCtx {
    /// Build a context for a buffer whose first byte sits at `base` in the
    /// overall frame.
    pub fn new(base: usize, unicode: bool) -> Self {
        DecodeCtx { base, unicode }
    }
}

/// Context used while encoding one frame.
#[derive(Debug, Clone, Copy)]
pub struct EncodeCtx {
    /// Absolute frame offset of the buffer being encoded.
    pub base: usize,
    /// Strings are UTF-16LE when set, otherwise OEM/ASCII.
    pub unicode: bool,
}

/// Implemented by on-wire structures so they can be read from / written to a
/// flat byte buffer without intermediate copies: decoding borrows variable
/// length data directly from `src`.
///
/// Implementations exist both for fixed-width primitives (`u16`, `u32`,
/// [`crate::types::FileTime`], …) and for dialect message bodies.
pub trait Wire<'de>: Sized {
    /// Parse one instance starting at `pos`; returns the value and the offset
    /// just past it.
    fn decode(src: &'de [u8], pos: usize) -> Result<(Self, usize), crate::error::ProtoError>;

    /// Append the encoded form to `dst`.
    fn encode(&self, dst: &mut Vec<u8>);

    /// Number of bytes this value occupies once encoded.
    fn encoded_len(&self) -> usize;
}

macro_rules! impl_wire_uint {
    ($($t:ty),*) => {$(
        impl<'de> Wire<'de> for $t {
            fn decode(src: &'de [u8], pos: usize) -> Result<(Self, usize), crate::error::ProtoError> {
                let n = std::mem::size_of::<$t>();
                if pos + n > src.len() {
                    return Err(crate::error::ProtoError::Overrun { need: n, at: pos, have: src.len() });
                }
                let mut v: $t = 0;
                for i in 0..n {
                    v |= (src[pos + i] as $t) << (8 * i);
                }
                Ok((v, pos + n))
            }
            fn encode(&self, dst: &mut Vec<u8>) {
                dst.extend_from_slice(&self.to_le_bytes());
            }
            fn encoded_len(&self) -> usize { std::mem::size_of::<$t>() }
        }
    )*};
}

impl_wire_uint!(u8, u16, u32, u64);

impl<'de> Wire<'de> for crate::types::FileTime {
    fn decode(src: &'de [u8], pos: usize) -> Result<(Self, usize), crate::error::ProtoError> {
        let (v, p) = <u64 as Wire<'de>>::decode(src, pos)?;
        Ok((crate::types::FileTime(v), p))
    }
    fn encode(&self, dst: &mut Vec<u8>) {
        self.0.encode(dst);
    }
    fn encoded_len(&self) -> usize {
        8
    }
}
