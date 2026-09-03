//! HMAC-MD5 ([RFC 2104] with MD5 as the hash function).
//!
//! The data is streamed: inner = MD5(ipad ‖ data) — the ipad block must be
//! hashed *together with* the message, not separately.

use super::md5::md5;

/// HMAC-MD5 of `data` under `key`; output is a 16-byte tag.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // HMAC-MD5 primitive ([RFC 2104])
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut key = key.to_vec();
    if key.len() > 64 {
        key = md5(&key).to_vec();
    }
    key.resize(64, 0);

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    // inner = MD5(ipad || data)
    let mut joined = Vec::with_capacity(64 + data.len());
    joined.extend_from_slice(&ipad);
    joined.extend_from_slice(data);
    let ih = md5(&joined);

    // outer = MD5(opad || inner)
    let mut both = Vec::with_capacity(64 + 16);
    both.extend_from_slice(&opad);
    both.extend_from_slice(&ih);
    md5(&both)
}

