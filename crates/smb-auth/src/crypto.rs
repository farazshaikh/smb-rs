//! Cryptographic primitives used by the NTLM family and SMB signing.
//!
//! Thin re-export of the [`smb_csp`] crypto service provider. The active
//! backend is selected at compile time in `smb-csp` itself:
//! * default — RustCrypto crates (`lib` feature),
//! * `--no-default-features --features handrolled` — bundled implementations.

pub use smb_csp::{
    aes128ccm_open, aes128ccm_seal,
    ntlm_mech_list_mic, aes128gcm_open, aes128gcm_seal, aes128_cmac,
    aes128_encrypt_block, des_encrypt_key7, hmac_md5, hmac_sha256,
    kdf_counter_mode_hmac_sha256, md4, md5, ntlmv1_response, nt_hash, rc4, sha256, sha512,
};

/// SHA-256 module alias for callers importing by path
/// (`crypto::sha256::sha256`).
pub mod sha256 {
    pub use smb_csp::sha256;
}

/// SHA-512 module alias for callers importing by path.
pub mod sha512 {
    pub use smb_csp::sha512;
}
