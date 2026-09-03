//! MD4 message digest ([RFC 1320]).

/// Compute the MD4 digest of `data`.
pub fn md4(data: &[u8]) -> [u8; 16] {
    // Round functions per RFC 1320 §3.3.x.
    fn round1(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, x: u32, s: u32) {
        let t = a.wrapping_add((*b & *c) | (!*b & *d)).wrapping_add(x);
        *a = t.rotate_left(s);
    }
    /// Round 2: G(X,Y,Z) = (X AND Y) OR (X AND Z) OR (Y AND Z).
    fn round2(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, x: u32, s: u32) {
        let t = a
            .wrapping_add((*b & *c) | (*b & *d) | (*c & *d))
            .wrapping_add(x.wrapping_add(0x5A82_7999));
        *a = t.rotate_left(s);
    }
    /// Round 3: H(X,Y,Z) = X XOR Y XOR Z.
    fn round3(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, x: u32, s: u32) {
        let t = a
            .wrapping_add(*b ^ *c ^ *d)
            .wrapping_add(x.wrapping_add(0x6ED9_EBA1));
        *a = t.rotate_left(s);
    }

    let mut state = [0x6745_2301u32, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, xi) in x.iter_mut().enumerate() {
            *xi = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) =
            (state[0], state[1], state[2], state[3]);

        // Round 1: words consumed strictly sequentially; the register roles
        // rotate (A,B,C,D)→(D,A,B,C) after every step.
        for j in 0..4 {
            let k = j * 4;
            round1(&mut a, &mut b, &mut c, &mut d, x[k], 3);
            round1(&mut d, &mut a, &mut b, &mut c, x[k + 1], 7);
            round1(&mut c, &mut d, &mut a, &mut b, x[k + 2], 11);
            round1(&mut b, &mut c, &mut d, &mut a, x[k + 3], 19);
        }
        // Round 2: word order 0,4,8,…,13 with majority function.
        let idx2 = [0usize, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
        for g in 0..4 {
            let k = g * 4;
            round2(&mut a, &mut b, &mut c, &mut d, x[idx2[k]], 3);
            round2(&mut d, &mut a, &mut b, &mut c, x[idx2[k + 1]], 5);
            round2(&mut c, &mut d, &mut a, &mut b, x[idx2[k + 2]], 9);
            round2(&mut b, &mut c, &mut d, &mut a, x[idx2[k + 3]], 13);
        }
        // Round 3: word order per RFC with XOR function.
        let idx3 = [0usize, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        for g in 0..4 {
            let k = g * 4;
            round3(&mut a, &mut b, &mut c, &mut d, x[idx3[k]], 3);
            round3(&mut d, &mut a, &mut b, &mut c, x[idx3[k + 1]], 9);
            round3(&mut c, &mut d, &mut a, &mut b, x[idx3[k + 2]], 11);
            round3(&mut b, &mut c, &mut d, &mut a, x[idx3[k + 3]], 15);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (i, v) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

