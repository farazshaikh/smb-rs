//! Protocol error type shared by all codecs.

use thiserror::Error;

/// Errors produced while encoding or decoding SMB structures.
#[derive(Debug, Error)]
pub enum ProtoError {
    /// Read or write past the end of the buffer.
    #[error("buffer overrun (need {need} bytes at offset {at}, have {have})")]
    Overrun {
        /// Bytes required by the field being parsed.
        need: usize,
        /// Absolute offset inside the frame where parsing stopped.
        at: usize,
        /// Total bytes available.
        have: usize,
    },
    /// A length, count or constant had an unexpected value.
    #[error("invalid value in field '{field}'")]
    InvalidField {
        /// Name of the offending field.
        field: &'static str,
    },
    /// A fixed magic marker did not match (e.g. `\xFFSMB`).
    #[error("bad magic value")]
    BadMagic,
}
