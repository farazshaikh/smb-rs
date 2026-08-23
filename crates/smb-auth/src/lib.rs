//! SMB authentication primitives.
//!
//! Contains the hand-rolled cryptographic helpers (MD4, MD5, HMAC-MD5, DES)
//! required by the NTLM family of authentication schemes, plus the
//! [MS-NLMP] NTLMSSP message construction/parsing and the minimal SPNEGO
//! DER wrapping used during extended-security session setup.
//!
//! These pieces are dialect-independent: SMB1 extended security and SMB2
//! session setup both speak SPNEGO + NTLMSSP.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

pub mod crypto;
pub mod ntlm;
