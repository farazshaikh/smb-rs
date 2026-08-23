//! Production backend: the maintained [RustCrypto] crates.
//!
//! Every function mirrors its bundled counterpart byte-for-byte; the
//! facade-level vectors in `lib.rs` enforce that for whichever backend is
//! compiled.
//!
//! [RustCrypto]: https://github.com/RustCrypto

use digest::KeyInit as _;
use hmac::Mac as _;
use sha2::Digest as _;

/// MD4 digest ([RFC 1320]).
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut h = md4::Md4::new();
    h.update(data);
    h.finalize().into()
}

/// MD5 digest ([RFC 1321]).
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = md5::Md5::new();
    h.update(data);
    h.finalize().into()
}

/// HMAC-MD5 of `data` under `key` ([RFC 2104]).
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <hmac::Hmac<md5::Md5> as hmac::KeyInit>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// SHA-256 digest ([FIPS 180-4]).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// SHA-512 digest ([FIPS 180-4]).
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = sha2::Sha512::new();
    h.update(data);
    h.finalize().into()
}

/// HMAC-SHA256 of `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m =
        <hmac::Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(key).expect("any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// XOR `data` with the RC4 keystream generated from `key`
/// ([MS-NLMP] §3.2.5.1.2 session-key transport).
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    /// The RustCrypto RC4 cipher is keyed by a compile-time key length;
    /// dispatch over the sizes that occur in practice (NTLM uses 16).
    macro_rules! rc4_dispatch {
        ($($len:expr => $ty:ident),+ $(,)?) => {
            match key.len() {
                $(
                    $len => {{
                        type C = rc4::Rc4<typenum::$ty>;
                        let mut c = <C as rc4::KeyInit>::new_from_slice(key)
                            .expect("length checked by dispatch");
                        let mut out = data.to_vec();
                        use rc4::StreamCipher as _;
                        c.apply_keystream(&mut out);
                        out
                    }}
                )+
                n => panic!("rc4: unsupported key length {n} (lib backend supports 1..=64)"),
            }
        };
    }
    rc4_dispatch! {
        1 => U1, 2 => U2, 3 => U3, 4 => U4, 5 => U5, 6 => U6, 7 => U7, 8 => U8,
        9 => U9, 10 => U10, 11 => U11, 12 => U12, 13 => U13, 14 => U14, 15 => U15,
        16 => U16, 17 => U17, 18 => U18, 19 => U19, 20 => U20, 21 => U21, 22 => U22,
        23 => U23, 24 => U24, 25 => U25, 26 => U26, 27 => U27, 28 => U28, 29 => U29,
        30 => U30, 31 => U31, 32 => U32,
    }
}

/// Expand a 56-bit NTLM key chunk (7 bytes) into an 8-byte DES key with
/// zero parity bits — one bit inserted after every seven ([MS-NLMP]
/// §3.3.1 / RFC 2437 style expansion used by LM/NTLMv1 responses).
fn key7_to_key8(k7: &[u8; 7]) -> [u8; 8] {
    let mut bits = [0u8; 56];
    let mut bit = 0usize;
    for byte in k7.iter() {
        for shift in (0..8).rev() {
            if bit == 56 {
                break;
            }
            bits[bit] = (byte >> shift) & 1;
            bit += 1;
        }
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        let mut b = 0u8;
        for j in 0..7 {
            b |= bits[i * 7 + j] << (7 - j);
        }
        out[i] = b; // LSB stays zero (parity position)
    }
    out
}

/// DES-ECB encrypt one block under a 56-bit NTLM key chunk.
pub fn des_encrypt_key7(key56: [u8; 7], plaintext: [u8; 8]) -> [u8; 8] {
    let key8 = key7_to_key8(&key56);
    let cipher = <des::Des as des::cipher::KeyInit>::new_from_slice(&key8)
        .expect("DES key is exactly 8 bytes");
    let mut block = des::cipher::Array::clone_from_slice(&plaintext);
    use des::cipher::BlockCipherEncrypt as _;
    cipher.encrypt_block(&mut block);
    block.into()
}

/// NTLMv1/LM response: three DES encryptions of the challenge under
/// successive 7-byte chunks of the 21-byte expanded hash ([MS-NLMP] §3.3.1).
pub fn ntlmv1_response(hash21: &[u8; 21], challenge: &[u8; 8]) -> [u8; 24] {
    let mut out = [0u8; 24];
    for i in 0..3 {
        let mut k = [0u8; 7];
        k.copy_from_slice(&hash21[i * 7..i * 7 + 7]);
        out[i * 8..i * 8 + 8].copy_from_slice(&des_encrypt_key7(k, *challenge));
    }
    out
}

/// Encrypt one 16-byte AES-128 block.
pub fn aes128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher =
        <aes::Aes128 as aes::cipher::KeyInit>::new_from_slice(key).expect("AES-128 key is 16 bytes");
    let mut b = aes::cipher::Array::clone_from_slice(block);
    use aes::cipher::BlockCipherEncrypt as _;
    cipher.encrypt_block(&mut b);
    b.into()
}

/// AES-CMAC over `data` under `key` ([RFC 4493]) — SMB 3.x signing.
pub fn aes128_cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut c =
        <cmac::Cmac<aes::Aes128> as digest::KeyInit>::new_from_slice(key).expect("any key length");
    use cmac::digest::Mac as _;
    c.update(data);
    c.finalize().into_bytes().into()
}
