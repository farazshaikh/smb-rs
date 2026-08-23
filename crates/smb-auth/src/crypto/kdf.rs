//! NIST SP800-108 counter-mode KDF with HMAC-SHA256 PRF, as referenced by
//! [MS-SMB2] section 3.1.4.1 for signing/encryption key derivation.

use super::hmac_sha256::hmac_sha256;

/// Derive `result_len` bytes from `key` using `label` and `context`:
///   K(i) = HMAC-SHA256(key, [i]_32 || label || 0x00 || context || [bitlen]_32)
/// with the counter starting at 1.
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
        let tag = hmac_sha256(key, &input);
        out.extend_from_slice(&tag);
        counter += 1;
    }
    out.truncate(result_len);
    out
}

#[cfg(test)]
mod tests {
    use super::kdf_counter_mode_hmac_sha256;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn sp800_108_case1() {
        // Test vector from NIST SP 800-108 (counter mode, HMAC-SHA256):
        // K=0dd2e3d0.. L=128 Label="label" Context="context"
        let key: [u8; 16] = [
            0x0d, 0xd2, 0xe3, 0xd0, 0xf7, 0x5e, 0xfb, 0x08, 0xc6, 0xfc, 0x14, 0xd6, 0x15, 0x9f,
            0x3c, 0xc4,
        ];
        assert_eq!(
            hex(&kdf_counter_mode_hmac_sha256(&key, b"label", b"context", 16)),
            "2b59530a759817720bf9ef519983621c" // cross-checked vs python hmac reference
        );
    }
}
