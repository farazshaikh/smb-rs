//! Crypto service provider for smb-server-rs.
//!
//! One stable API surface, two interchangeable backends selected at compile
//! time:
//!
//! * **`lib` (default)** — maintained [RustCrypto] crates. Hardware
//!   acceleration (AES-NI et al.) where available; the production choice.
//! * **`handrolled`** — the bundled from-scratch implementations. Zero
//!   external dependencies, useful for auditing or constrained builds.
//!
//! ```text
//! cargo build -p smb-server-csp                 # RustCrypto backend
//! cargo build -p smb-server-csp --no-default-features --features handrolled
//! ```
//!
//! Both backends must produce byte-identical output; the test vectors in
//! this file are asserted for whichever backend is compiled.
//!
//! [RustCrypto]: https://github.com/RustCrypto

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

#[cfg(all(feature = "lib", feature = "handrolled"))]
compile_error!("select exactly one CSP backend: 'lib' (default) or 'handrolled'");

#[cfg(not(any(feature = "lib", feature = "handrolled")))]
compile_error!("select exactly one CSP backend: 'lib' (default) or 'handrolled'");

#[cfg(feature = "lib")]
mod lib_backend;

#[cfg(feature = "lib")]
pub use lib_backend::*;

#[cfg(feature = "lib")]
pub(crate) mod csp_call {
    pub fn md4(data: &[u8]) -> [u8; 16] { crate::lib_backend::md4(data) }
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] { crate::lib_backend::hmac_sha256(key, data) }
}

#[cfg(feature = "handrolled")]
mod bundled {
    pub mod aes128;
    pub mod des;
    pub mod hmac;
    pub mod hmac_sha256;
    pub mod md4;
    pub mod md5;
    pub mod rc4;
    pub mod sha256;
    pub mod sha512;
}

#[cfg(feature = "handrolled")]
mod backend {
    pub use super::bundled::aes128::{aes128_cmac, aes128_encrypt_block};
    pub use super::bundled::des::{des_encrypt_key7, ntlmv1_response};
    pub use super::bundled::hmac::hmac_md5;
    pub use super::bundled::hmac_sha256::hmac_sha256;
    pub use super::bundled::md4::md4;
    pub use super::bundled::md5::md5;
    pub use super::bundled::rc4::rc4;
    pub use super::bundled::sha256::sha256;
    pub use super::bundled::sha512::sha512;
}

#[cfg(feature = "handrolled")]
pub use backend::*;

#[cfg(feature = "handrolled")]
pub(crate) mod csp_call {
    pub fn md4(data: &[u8]) -> [u8; 16] { super::backend::md4(data) }
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] { super::backend::hmac_sha256(key, data) }
}


/// NT hash = MD4 of the UTF-16LE encoded password ([MS-NLMP] §3.3.1.1).
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // MD4 of UTF-16LE password
pub fn nt_hash(password: &str) -> [u8; 16] {
    let mut bytes = Vec::with_capacity(password.len() * 2);
    for u in password.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    crate::csp_call::md4(&bytes)
}

/// SP800-108 counter-mode KDF with HMAC-SHA256 PRF ([MS-SMB2] §3.1.4.1):
///   K(i) = HMAC-SHA256(key, [i]_32BE || label || 0x00 || context || [L]_32BE)
///
/// This is protocol plumbing on top of the backend primitive rather than a
/// primitive itself, so it is shared by both backends unchanged.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SP800-108 counter-mode KDF
pub fn kdf_counter_mode_hmac_sha256(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    result_len: usize,
) -> Vec<u8> {
    let bitlen = (result_len as u32) * 8;
    let mut out = Vec::with_capacity(result_len);
    let mut counter: u32 = 1;
    while out.len() < result_len {
        let mut input = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(label);
        input.push(0);
        input.extend_from_slice(context);
        input.extend_from_slice(&bitlen.to_be_bytes());
        let tag = crate::csp_call::hmac_sha256(key, &input);
        out.extend_from_slice(&tag);
        counter += 1;
    }
    out.truncate(result_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    // Golden values captured from the bundled implementations and, where
    // applicable, cross-checked against FIPS / RFC / well-known references.
    // BOTH backends must satisfy every assertion below.

    #[test]
    fn nt_hash_vector() {
        assert_eq!(hex(&nt_hash("password")), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn md4_vector() {
        assert_eq!(hex(&md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(
            hex(&md4(b"")),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );
    }

    #[test]
    fn md5_vector() {
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn hmac_md5_rfc2202() {
        assert_eq!(
            hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }

    #[test]
    fn sha2_vectors() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231() {
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rc4_vector() {
        assert_eq!(
            hex(&rc4(&[1u8, 2, 3, 4, 5], &[0u8; 16])),
            "b2396305f03dc027ccc3524a0a1118a8"
        );
    }

    #[test]
    fn ntlmv1_golden() {
        // Verified against OpenSSL DES-ECB with the standard 7->8 bit
        // parity-expanded key (the original bundled schedule was wrong).
        let h21 = [7u8; 21];
        let challenge = [3u8; 8];
        assert_eq!(
            hex(&ntlmv1_response(&h21, &challenge)),
            "23f68ad3636db29e23f68ad3636db29e23f68ad3636db29e" // verified vs impacket get_ntlmv1_response
        );
    }

    #[test]
    fn aes_block_fips197() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(
            hex(&aes128_encrypt_block(&key, &pt)),
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        );
    }

    #[test]
    fn cmac_vectors() {
        let key: [u8; 16] = [
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42,
        ];
        // Goldens captured from the original bundled implementation.
        assert_eq!(hex(&aes128_cmac(&key, &[])), "565aa8245bc3cf6d60f4f3e9d52921dd");
        let msg16: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        assert_eq!(
            hex(&aes128_cmac(&key, &msg16)),
            "de1d864d75b61033c28628c18f6048f8"
        );
        // RFC 4493 canonical key cross-check (validated against an external
        // CMAC implementation during development).
        let rfc_key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        assert_eq!(
            hex(&aes128_cmac(&rfc_key, &msg16)),
            "070a16b46b4d4144f79bdd9dd04a287c"
        );
    }

    #[test]
    fn kdf_cross_checked() {
        // Value cross-checked against an independent Python reference
        // (hmac/hashlib) implementing SP800-108 counter mode.
        let key: [u8; 16] = [
            0x0d, 0xd2, 0xe3, 0xd0, 0xf7, 0x5e, 0xfb, 0x08, 0xc6, 0xfc, 0x14, 0xd6, 0x15, 0x9f,
            0x3c, 0xc4,
        ];
        assert_eq!(
            hex(&kdf_counter_mode_hmac_sha256(&key, b"label", b"context", 16)),
            "2b59530a759817720bf9ef519983621c"
        );
    }

    #[cfg(feature = "lib")]
    #[test]
    fn aes256_seal_open_roundtrip() {
        let key = [0x11u8; 32];
        let aad = b"transform-header-aad";
        let pt = b"AES-256 sealed SMB payload";

        let g = aes256gcm_seal(&key, &[0x22u8; 12], aad, pt);
        assert_eq!(
            aes256gcm_open(&key, &[0x22u8; 12], aad, &g).as_deref(),
            Some(&pt[..])
        );
        // A wrong key must not open the frame.
        assert!(aes256gcm_open(&[0u8; 32], &[0x22u8; 12], aad, &g).is_none());

        let c = aes256ccm_seal(&key, &[0x33u8; 11], aad, pt);
        assert_eq!(
            aes256ccm_open(&key, &[0x33u8; 11], aad, &c).as_deref(),
            Some(&pt[..])
        );
        // Tampered AAD must fail authentication.
        assert!(aes256ccm_open(&key, &[0x33u8; 11], b"other-aad", &c).is_none());
    }
}
