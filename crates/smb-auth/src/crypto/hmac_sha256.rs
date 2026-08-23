//! HMAC-SHA256 ([RFC 2104] with SHA-256). Used for SMB2 message
//! signatures (dialects 2.0.2–2.1.0) and NTLM key derivation.

use super::sha256::sha256;

/// HMAC-SHA256 of `data` under `key`; output is a 32-byte tag.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key = key.to_vec();
    if key.len() > 64 {
        key = sha256(&key).to_vec();
    }
    key.resize(64, 0);

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    // inner = SHA256(ipad || data)
    let mut joined = Vec::with_capacity(64 + data.len());
    joined.extend_from_slice(&ipad);
    joined.extend_from_slice(data);
    let ih = sha256(&joined);

    // outer = SHA256(opad || inner)
    let mut both = Vec::with_capacity(64 + 32);
    both.extend_from_slice(&opad);
    both.extend_from_slice(&ih);
    sha256(&both)
}

#[cfg(test)]
mod tests {
    use super::hmac_sha256;

    fn hex(d: [u8; 32]) -> String {
        d.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn rfc4231_case2() {
        assert_eq!(
            hex(hmac_sha256(
                b"Jefe",
                b"what do ya want for nothing?"
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
