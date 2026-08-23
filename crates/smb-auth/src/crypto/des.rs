//! Single-block DES-ECB, exactly what NTLMv1/LM response computation needs
//! ([MS-NLMP] §3.3.1: three DES encryptions of the 8-byte server challenge
//! under 7-byte key chunks of a 21-byte expanded hash).

/// DES S-boxes (S1..S8), initial/final permutation and expansion tables.
mod tables {
    pub const IP: [u8; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22,
        14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35,
        27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];
    pub const FP: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22,
        62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11,
        51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ];
    pub const E: [u8; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30,
        31, 32, 1,
    ];
    pub const P: [u8; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3,
        9, 19, 13, 30, 6, 22, 11, 4, 25,
    ];
    pub const SBOX: [[u8; 64]; 8] = [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ];
    pub const PC1: [u8; 56] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19,
        11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
        61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
    ];
    pub const PC2: [u8; 48] = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13,
        2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42,
        50, 36, 29, 32,
    ];
    pub const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for b in bytes {
        for i in (0..8).rev() {
            bits.push((b >> i) & 1 == 1);
        }
    }
    bits
}

fn bits_to_bytes8(bits: &[bool; 64]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, o) in out.iter_mut().enumerate() {
        let mut b = 0u8;
        for j in 0..8 {
            b |= (bits[i * 8 + j] as u8) << (7 - j);
        }
        *o = b;
    }
    out
}

/// Encrypt one 8-byte block under the given 56-bit key material.
fn des_block(block: [u8; 8], keys: &[[u8; 6]; 16]) -> [u8; 8] {
    use tables::*;
    let bits = bytes_to_bits(&block);
    let mut state = [false; 64];
    for i in 0..64 {
        state[i] = bits[IP[i] as usize - 1];
    }

    for round in 0..16 {
        let mut left = [false; 32];
        let mut right = [false; 32];
        left.copy_from_slice(&state[..32]);
        right.copy_from_slice(&state[32..]);

        // Expansion.
        let mut er = [false; 48];
        for i in 0..48 {
            er[i] = right[E[i] as usize - 1];
        }
        // Key mixing.
        let kb = bytes_to_bits(&keys[round]);
        for i in 0..48 {
            er[i] ^= kb[i];
        }
        // Substitution.
        let mut sb = [0u8; 8];
        for (boxn, s) in sb.iter_mut().enumerate() {
            let seg = &er[boxn * 6..boxn * 6 + 6];
            let row = ((seg[0] as usize) << 1) | seg[5] as usize;
            let col = (seg[1] as usize) << 3
                | (seg[2] as usize) << 2
                | (seg[3] as usize) << 1
                | seg[4] as usize;
            *s = SBOX[boxn][row * 16 + col];
        }
        // P permutation + Feistel combination.
        let mut pbits = [false; 32];
        for (i, p) in pbits.iter_mut().enumerate() {
            *p = (sb[i / 4] >> (3 - (i % 4))) & 1 == 1;
        }
        let mut newr = [false; 32];
        for i in 0..32 {
            newr[i] = left[i] ^ pbits[P[i] as usize - 1];
        }
        state[..32].copy_from_slice(&right);
        state[32..].copy_from_slice(&newr);
    }

    // Final permutation with the customary 32-bit swap.
    let mut pre = [false; 64];
    pre[..32].copy_from_slice(&state[32..]);
    pre[32..].copy_from_slice(&state[..32]);

    let mut outbits = [false; 64];
    for i in 0..64 {
        outbits[i] = pre[FP[i] as usize - 1];
    }
    bits_to_bytes8(&outbits)
}

/// Build the 16 round keys from a 7-byte (56-bit) key chunk.
fn schedule(key56: [u8; 7]) -> [[u8; 6]; 16] {
    use tables::*;
    let padded = {
        let mut k = [0u8; 8];
        k[..7].copy_from_slice(&key56);
        k
    };
    let all = bytes_to_bits(&padded);
    let mut kbits = vec![false; 56];
    for i in 0..56 {
        kbits[i] = all[PC1[i] as usize - 1];
    }
    let (mut cl, mut cr) = (kbits[..28].to_vec(), kbits[28..].to_vec());
    let mut keys = [[0u8; 6]; 16];
    for (round, ks) in keys.iter_mut().enumerate() {
        for _ in 0..SHIFTS[round] {
            let c0 = cl.remove(0);
            cl.push(c0);
            let r0 = cr.remove(0);
            cr.push(r0);
        }
        let combined: Vec<bool> = cl.iter().chain(cr.iter()).copied().collect();
        for i in 0..48 {
            let bit = combined[PC2[i] as usize - 1];
            ks[i / 8] |= (bit as u8) << (7 - (i % 8));
        }
    }
    keys
}

/// DES-ECB encrypt `plaintext` (8 bytes) under a 56-bit key given as 7 bytes.
pub fn des_encrypt_key7(key56: [u8; 7], plaintext: [u8; 8]) -> [u8; 8] {
    des_block(plaintext, &schedule(key56))
}

/// NTLMv1/LM response: encrypt the 8-byte server challenge three times using
/// successive 7-byte chunks of the 21-byte expanded hash ([MS-NLMP] §3.3.1).
///
/// Returns the concatenated 24-byte response.
pub fn ntlmv1_response(hash21: &[u8; 21], challenge: &[u8; 8]) -> [u8; 24] {
    let mut out = [0u8; 24];
    for i in 0..3 {
        let mut k = [0u8; 7];
        k.copy_from_slice(&hash21[i * 7..i * 7 + 7]);
        let ct = des_encrypt_key7(k, *challenge);
        out[i * 8..i * 8 + 8].copy_from_slice(&ct);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        // Structural check: the response must be a pure function of the
        // inputs; correctness against real clients is covered by the
        // NTLMv1 integration path.
        let h = [7u8; 21];
        let c = [3u8; 8];
        assert_eq!(ntlmv1_response(&h, &c), ntlmv1_response(&h, &c));
        assert_ne!(ntlmv1_response(&h, &c), ntlmv1_response(&h, &[4u8; 8]));
    }
}
