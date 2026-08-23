//! Hand-rolled cryptographic primitives for NTLM authentication.
//!
//! Only what NTLM needs: MD4 (NT hash), MD5 + HMAC-MD5 (NTLMv2 proofs,
//! session keys) and single-block DES (NTLMv1/LM responses). All are direct
//! implementations of the published algorithm definitions ([RFC 1320] for
//! MD4, [RFC 1321] for MD5, FIPS 46-3 for DES).

pub mod des;
pub mod hmac;
pub mod md4;
pub mod md5;

pub use des::{des_encrypt_key7, ntlmv1_response};
pub use hmac::hmac_md5;
pub use md4::md4;
pub use md5::md5;

/// NT hash = MD4 of the UTF-16LE encoded password ([MS-NLMP] §3.3.1.1).
pub fn nt_hash(password: &str) -> [u8; 16] {
    let mut bytes = Vec::with_capacity(password.len() * 2);
    for u in password.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    md4(&bytes)
}
