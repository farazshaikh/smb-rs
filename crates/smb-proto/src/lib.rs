//! Dialect-neutral SMB protocol primitives.
//!
//! This crate hosts the pieces every SMB dialect shares: the codec trait used
//! by all on-wire structures, NT status codes, FILETIME conversion and the
//! byte-buffer helpers that implement SMB's string/alignment rules.
//!
//! Dialect-specific message layouts live in [`smb-proto-smb1`],
//! `smb-proto-smb2`, … and implement [`wire::Wire`] (or a dialect body trait)
//! on top of these primitives.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

pub mod buf;
pub mod error;
pub mod types;
pub mod wire;
