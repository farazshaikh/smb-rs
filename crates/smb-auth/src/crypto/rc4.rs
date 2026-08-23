//! RC4 ([Schneier, Applied Cryptography]) — the stream cipher NTLM uses to
//! transport the exported session key when NEGOTIATE_KEY_EXCH is set
//! ([MS-NLMP] §3.2.5.1.2).

/// XOR `data` with the RC4 keystream generated from `key`.
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    // KSA
    let mut s: [u8; 256] = [0; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }

    // PRGA
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    let mut jj = 0usize;
    for b in data {
        i = (i + 1) & 0xff;
        jj = (jj + s[i] as usize) & 0xff;
        s.swap(i, jj);
        out.push(b ^ s[(s[i] as usize + s[jj] as usize) & 0xff]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::rc4;

    #[test]
    fn fips_vector() {
        // FIPS 197-style test vector widely published for RC4:
        // key=0x01..0x05, plaintext zeros → known keystream prefix.
        let ks = rc4(&[1u8, 2, 3, 4, 5], &[0u8; 16]);
        assert_eq!(
            ks.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            "b2396305f03dc027ccc3524a0a1118a8"
        );
    }

    #[test]
    fn symmetric() {
        let ct = rc4(b"secret-key", b"attack at dawn");
        assert_eq!(rc4(b"secret-key", &ct), b"attack at dawn");
    }
}
