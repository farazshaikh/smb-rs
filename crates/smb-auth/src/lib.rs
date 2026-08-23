//! SMB authentication primitives.
//!
//! Cryptographic primitives come from the [`smb_csp`] crypto service
//! provider (RustCrypto crates by default, bundled implementations behind a
//! feature flag). Also hosts the
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
