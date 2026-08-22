// Minimal pure-Rust crypto for NTLM: MD4, MD5, HMAC-MD5 and DES.
// Used to verify NTLMv1/NTLMv2/NTLMSSP responses against a challenge.

// ---------------- MD4 ----------------
pub fn md4(data: &[u8]) -> [u8; 16] {
    struct Md4 {
        state: [u32; 4],
    }
    fn round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, x: u32, s: u32) {
        let t = a
            .wrapping_add((*b & *c) | (!*b & *d))
            .wrapping_add(x);
        *a = t.rotate_left(s);
    }
    // RFC 1320: round 2 uses majority(B,C,D) with constant 0x5A827999;
    // round 3 uses XOR with 0x6ED9EBA1.
    fn round2(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, x: u32, s: u32) {
        let t = a
            .wrapping_add((*b & *c) | (*b & *d) | (*c & *d))
            .wrapping_add(x.wrapping_add(0x5A82_7999));
        *a = t.rotate_left(s);
    }
    fn round3(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, x: u32, s: u32) {
        let t = a
            .wrapping_add(*b ^ *c ^ *d)
            .wrapping_add(x.wrapping_add(0x6ED9_EBA1));
        *a = t.rotate_left(s);
    }

    let mut m = Md4 {
        state: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476],
    };

    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (
            m.state[0],
            m.state[1],
            m.state[2],
            m.state[3],
        );
        for s in [0usize, 8, 4, 12].iter() {}
        // Round 1
        for i in 0..4 {
            let j = i * 4;
            round(&mut a, &mut b, &mut c, &mut d, x[j], 3);
            round(&mut d, &mut a, &mut b, &mut c, x[j + 1], 7);
            round(&mut c, &mut d, &mut a, &mut b, x[j + 2], 11);
            round(&mut b, &mut c, &mut d, &mut a, x[j + 3], 19);
        }
        // Round 2
        let idx2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
        for k in 0..4 {
            let i = k * 4;
            round2(&mut a, &mut b, &mut c, &mut d, x[idx2[i]], 3);
            round2(&mut d, &mut a, &mut b, &mut c, x[idx2[i + 1]], 5);
            round2(&mut c, &mut d, &mut a, &mut b, x[idx2[i + 2]], 9);
            round2(&mut b, &mut c, &mut d, &mut a, x[idx2[i + 3]], 13);
        }
        // Round 3
        let idx3 = [
            0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15,
        ];
        for k in 0..4 {
            let i = k * 4;
            round3(&mut a, &mut b, &mut c, &mut d, x[idx3[i]], 3);
            round3(&mut d, &mut a, &mut b, &mut c, x[idx3[i + 1]], 9);
            round3(&mut c, &mut d, &mut a, &mut b, x[idx3[i + 2]], 11);
            round3(&mut b, &mut c, &mut d, &mut a, x[idx3[i + 3]], 15);
        }
        m.state[0] = m.state[0].wrapping_add(a);
        m.state[1] = m.state[1].wrapping_add(b);
        m.state[2] = m.state[2].wrapping_add(c);
        m.state[3] = m.state[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for i in 0..4 {
        out[i * 4..i * 4 + 4].copy_from_slice(&m.state[i].to_le_bytes());
    }
    out
}

pub fn nt_hash(password: &str) -> [u8; 16] {
    let utf16: Vec<u16> = password.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for u in utf16 {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    md4(&bytes)
}

// ---------------- MD5 ----------------
struct Md5Ctx {
    state: [u32; 4],
    buf: [u8; 64],
    buflen: usize,
    total: u64,
}

impl Md5Ctx {
    fn new() -> Self {
        Md5Ctx {
            state: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476],
            buf: [0; 64],
            buflen: 0,
            total: 0,
        }
    }

    fn block(&mut self, chunk: &[u8]) {
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14,
            20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11,
            16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (
            self.state[0],
            self.state[1],
            self.state[2],
            self.state[3],
        );
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let k: u32 = [
                0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
                0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
                0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
                0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
                0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
                0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
            ][i];
            let sum = a
                .wrapping_add(f)
                .wrapping_add(k)
                .wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = tmp;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.buflen > 0 {
            let need = 64 - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                let blk = self.buf;
                self.block(&blk);
                self.buflen = 0;
            }
        }
        while data.len() >= 64 {
            let (blk, rest) = data.split_at(64);
            self.block(blk);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    fn finish(mut self) -> [u8; 16] {
        let bitlen = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buflen != 56 {
            self.update(&[0]);
        }
        let lb = bitlen.to_le_bytes();
        self.update(&lb);
        let mut out = [0u8; 16];
        for i in 0..4 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_le_bytes());
        }
        out
    }
}

pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut ctx = Md5Ctx::new();
    ctx.update(data);
    ctx.finish()
}

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
    let mut inner = Md5Ctx::new();
    inner.update(&ipad);
    inner.update(data);
    let ih = inner.finish();
    let mut outer = Md5Ctx::new();
    outer.update(&opad);
    outer.update(&ih);
    outer.finish()
}

// ---------------- DES (single-block ECB, used by NTLMv1/LM) ----------------
mod des_tables {
    pub const IP: [u8; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14,
        6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19,
        11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];
    pub const FP: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62,
        30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19,
        59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ];
    pub const E: [u8; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16,
        17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,
        1,
    ];
    pub const P: [u8; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25,
    ];
    pub const SBOX: [[u8; 64]; 8] = [
        [
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10,
            6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12,
            8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
        ],
        [
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12,
            0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8,
            10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
        ],
        [
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8,
            5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10,
            13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
        ],
        [
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4,
            7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15,
            0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
        ],
        [
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5,
            0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8,
            12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
        ],
        [
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6,
            1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3,
            2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        ],
        [
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14,
            3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11,
            13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
        ],
        [
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12,
            5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1,
            14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
        ],
    ];
    pub const PC1: [u8; 56] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11,
        3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53,
        45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
    ];
    pub const PC2: [u8; 48] = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36,
        29, 32,
    ];
    pub const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
}

fn bits_to_bytes_le(bits: &[bool; 64]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for i in 0..8 {
        let mut b = 0u8;
        for j in 0..8 {
            b |= (bits[i * 8 + j] as u8) << (7 - j);
        }
        out[i] = b;
    }
    out
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

fn des_block(block: [u8; 8], keys: &[[u8; 6]; 16]) -> [u8; 8] {
    use des_tables::*;
    let bits = bytes_to_bits(&block);
    let mut ip = [false; 64];
    for i in 0..64 {
        ip[i] = bits[IP[i] as usize - 1];
    }
    let mut lr = ip;
    for round in 0..16 {
        let mut l = [false; 32];
        let mut r = [false; 32];
        l.copy_from_slice(&lr[..32]);
        r.copy_from_slice(&lr[32..]);
        // Expand
        let mut er = [false; 48];
        for i in 0..48 {
            er[i] = r[E[i] as usize - 1];
        }
        // XOR with key
        let kb = bytes_to_bits(&keys[round]);
        for i in 0..48 {
            er[i] ^= kb[i];
        }
        // S-boxes
        let mut sb = [0u8; 8];
        for boxn in 0..8 {
            let seg = &er[boxn * 6..boxn * 6 + 6];
            let row = (seg[0] as usize) << 1 | seg[5] as usize;
            let col = (seg[1] as usize) << 3
                | (seg[2] as usize) << 2
                | (seg[3] as usize) << 1
                | seg[4] as usize;
            sb[boxn] = SBOX[boxn][row * 16 + col];
        }
        // P permutation
        let mut pbits = [false; 32];
        for i in 0..8 {
            for j in 0..4 {
                pbits[i * 4 + j] = (sb[i] >> (3 - j)) & 1 == 1;
            }
        }
        let mut fp = [false; 32];
        for i in 0..32 {
            fp[i] = pbits[P[i] as usize - 1];
        }
        let mut newr = [false; 32];
        for i in 0..32 {
            newr[i] = l[i] ^ fp[i];
        }
        lr[..32].copy_from_slice(&r);
        lr[32..].copy_from_slice(&newr);
    }
    // Final permutation with 32-bit swap applied
    let mut pre = [false; 64];
    pre[..32].copy_from_slice(&lr[32..]);
    pre[32..].copy_from_slice(&lr[..32]);
    let mut outbits = [false; 64];
    for i in 0..64 {
        outbits[i] = pre[FP[i] as usize - 1];
    }
    bits_to_bytes_le(&outbits)
}

/// Encrypt one 8-byte block with the given 7-byte-per-8 key schedule input.
fn des_encrypt_key(key56: [u8; 7], plaintext: [u8; 8]) -> [u8; 8] {
    use des_tables::*;
    // Build 56-bit key
    let mut kbits = vec![false; 56];
    {
        let all = bytes_to_bits(&{
            let mut k = [0u8; 8];
            k[..7].copy_from_slice(&key56);
            k
        });
        for i in 0..56 {
            kbits[i] = all[PC1[i] as usize - 1];
        }
    }
    let mut keys = [[0u8; 6]; 16];
    let (mut cl, mut cr) = (kbits[..28].to_vec(), kbits[28..].to_vec());
    for round in 0..16 {
        for _ in 0..SHIFTS[round] {
            let cl0 = cl.remove(0);
            cl.push(cl0);
            let cr0 = cr.remove(0);
            cr.push(cr0);
        }
        let combined: Vec<bool> = cl.iter().chain(cr.iter()).copied().collect();
        let mut subkey = [false; 48];
        for i in 0..48 {
            subkey[i] = combined[PC2[i] as usize - 1];
        }
        // pack into 6 bytes
        let mut kb = [0u8; 6];
        for i in 0..48 {
            kb[i / 8] |= (subkey[i] as u8) << (7 - (i % 8));
        }
        keys[round] = kb;
    }
    des_block(plaintext, &keys)
}

/// NTLMv1 LM/NT response computation: three DES blocks over the challenge
/// using 7-byte chunks of a 21-byte expanded hash.
pub fn ntlmv1_response(hash21: &[u8; 21], challenge: &[u8; 8]) -> [u8; 24] {
    let mut out = [0u8; 24];
    for i in 0..3 {
        let mut k = [0u8; 7];
        k.copy_from_slice(&hash21[i * 7..i * 7 + 7]);
        let pt = [
            challenge[0],
            challenge[1],
            challenge[2],
            challenge[3],
            challenge[4],
            challenge[5],
            challenge[6],
            challenge[7],
        ];
        let ct = des_encrypt_key(k, pt);
        out[i * 8..i * 8 + 8].copy_from_slice(&ct);
    }
    out
}
