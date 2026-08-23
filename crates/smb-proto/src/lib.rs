//! Dialect-neutral SMB protocol primitives.
//!
//! This crate hosts the pieces every SMB dialect shares: the [`Wire`] codec
//! trait used by all on-wire structures, explicit-endian integer readers,
//! NT status codes, FILETIME conversion and the byte-buffer helpers that
//! implement SMB's string/alignment rules.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

pub mod buf;
pub mod endian;
pub mod error;
pub mod types;
pub mod wire;
