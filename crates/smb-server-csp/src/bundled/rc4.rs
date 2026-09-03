//! RC4 ([Schneier, Applied Cryptography]) — the stream cipher NTLM uses to
//! transport the exported session key when NEGOTIATE_KEY_EXCH is set
//! ([MS-NLMP] §3.2.5.1.2).

/// XOR `data` with the RC4 keystream generated from `key`.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // RC4 stream cipher primitive ([MS-NLMP] key exchange)
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

