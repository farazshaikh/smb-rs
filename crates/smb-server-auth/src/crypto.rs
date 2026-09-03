//! Cryptographic primitives used by the NTLM family and SMB signing.
//!
//! Thin re-export of the [`smb_server_csp`] crypto service provider. The active
//! backend is selected at compile time in `smb-server-csp` itself:
//! * default — RustCrypto crates (`lib` feature),
//! * `--no-default-features --features handrolled` — bundled implementations.

#[cfg(feature = "lib")]
pub use smb_server_csp::{aes128ccm_open, aes128ccm_seal, aes128gcm_open, aes128gcm_seal,
    aes256ccm_open, aes256ccm_seal, aes256gcm_open, aes256gcm_seal,
    ntlm_mech_list_mic};

/// AES-128-GMAC authentication tag over `msg` with `nonce` ([RFC4543]): the
/// SMB 3.1.1 AES-GMAC signature ([MS-SMB2] §3.1.4.1). GMAC is AES-GCM with an
/// empty plaintext and the message supplied as additional authenticated data;
/// the 16-byte GCM tag is the signature.
#[cfg(feature = "lib")]
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // AEAD tag length
pub fn aes128_gmac(key: &[u8; 16], nonce: &[u8; 12], msg: &[u8]) -> [u8; 16] {
    let out = aes128gcm_seal(key, nonce, msg, &[]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&out[out.len() - 16..]);
    tag
}
pub use smb_server_csp::{
    aes128_cmac,
    aes128_encrypt_block, des_encrypt_key7, hmac_md5, hmac_sha256,
    kdf_counter_mode_hmac_sha256, md4, md5, ntlmv1_response, nt_hash, rc4, sha256, sha512,
};

/// SHA-256 module alias for callers importing by path
/// (`crypto::sha256::sha256`).
pub mod sha256 {
    pub use smb_server_csp::sha256;
}

/// SHA-512 module alias for callers importing by path.
pub mod sha512 {
    pub use smb_server_csp::sha512;
}
