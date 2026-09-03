//! Codec trait for on-wire structures.
//!
//! Every SMB message structure implements [`Wire`], providing:
//! - `decode`: parse from a byte slice, **borrowing** variable-length data
//!   (zero-copy — no intermediate copies)
//! - `encode`: serialize into a growable byte buffer
//!
//! Endianness is handled explicitly via [`endian`] helpers (`from_le_bytes`
//! / `to_le_bytes`) rather than native casting, so the code is correct on
//! any host architecture.

use crate::error::ProtoError;

/// Context threaded through encode/decode calls.
///
/// Carries information that affects how individual fields are interpreted:
/// Unicode string mode, absolute frame offsets (for parity), dialect.
#[derive(Debug, Clone, Copy)]
pub struct Ctx {
    /// Absolute frame offset corresponding to the start of the buffer
    /// being decoded. Used for Unicode parity alignment.
    pub base: usize,
    /// Strings are UTF-16LE when set, otherwise OEM/ASCII.
    pub unicode: bool,
}

impl Ctx {
    /// New context with the given frame base offset and string mode.
    pub fn new(base: usize, unicode: bool) -> Self {
        Ctx { base, unicode }
    }

    /// True if the absolute position `abs` is odd relative to the frame base.
    pub fn is_odd(&self, abs: usize) -> bool {
        abs & 1 != 0
    }
}

/// Codec trait for fixed-layout and variable-layout on-wire structures.
///
/// The `'de` lifetime ties decoded variable-length data (names, blobs) to
/// the input buffer, enabling zero-copy parsing.
pub trait Wire<'de>: Sized {
    /// Decode one instance starting at `pos` within `src`.
    ///
    /// Returns the parsed value and the offset immediately past it.
    /// Variable-length fields are borrowed from `src`.
    fn decode(src: &'de [u8], pos: usize, ctx: &Ctx) -> Result<(Self, usize), ProtoError>;

    /// Append the encoded form to `dst`.
    fn encode(&self, dst: &mut Vec<u8>, ctx: &Ctx);

    /// Number of bytes this value occupies in its encoded form.
    fn encoded_len(&self) -> usize;
}

/// Fixed-width unsigned integer implementations.
macro_rules! impl_wire_int {
    ($($ty:ty),*) => {$(
        impl<'de> Wire<'de> for $ty {
            #[inline]
            fn decode(src: &'de [u8], pos: usize, _ctx: &Ctx) -> Result<(Self, usize), ProtoError> {
                let sz = std::mem::size_of::<$ty>();
                if pos + sz > src.len() {
                    return Err(ProtoError::Overrun { need: sz, at: pos, have: src.len() });
                }
                let mut raw = [0u8; std::mem::size_of::<$ty>()];
                raw.copy_from_slice(&src[pos..pos + sz]);
                Ok((<$ty>::from_le_bytes(raw), pos + sz))
            }
            #[inline]
            fn encode(&self, dst: &mut Vec<u8>, _ctx: &Ctx) {
                dst.extend_from_slice(&self.to_le_bytes());
            }
            #[inline]
            fn encoded_len(&self) -> usize { std::mem::size_of::<$ty>() }
        }
    )*};
}

impl_wire_int!(u8, u16, u32, u64);
