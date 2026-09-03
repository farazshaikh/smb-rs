//! AES-128 block cipher ([FIPS 197]) — forward encrypt block only, which is
//! all AES-CMAC (SMB3 signing) requires.

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
    0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
    0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
    0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
    0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
    0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
    0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
    0x16,
];

#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // AES-128 block cipher primitive
fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

/// Expand a 16-byte AES-128 key into the 11 round keys (176 bytes).
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // AES-128 block cipher primitive
fn expand_key(key: &[u8; 16]) -> Vec<[u8; 16]> {
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        w[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
    }
    let mut rcon = 1u8;
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            t = [SBOX[t[1] as usize], SBOX[t[2] as usize], SBOX[t[3] as usize], SBOX[t[0] as usize]];
            t[0] ^= rcon;
            rcon = xtime(rcon);
        }
        for j in 0..4 {
            w[i][j] = w[i - 4][j] ^ t[j];
        }
    }
    (0..11)
        .map(|r| {
            let mut rk = [0u8; 16];
            for i in 0..4 {
                rk[i * 4..i * 4 + 4].copy_from_slice(&w[r * 4 + i]);
            }
            rk
        })
        .collect()
}

/// Encrypt one 16-byte block under `key`.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // AES-128 block cipher primitive
pub fn aes128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let round_keys = expand_key(key);
    // State column-major as FIPS 197: state[r][c] = block[c*4+r].
    let mut s = [0u8; 16];
    s.copy_from_slice(block);

    fn add_round_key(s: &mut [u8; 16], rk: &[u8; 16]) {
        for i in 0..16 {
            s[i] ^= rk[i];
        }
    }
    fn sub_bytes(s: &mut [u8; 16]) {
        for b in s.iter_mut() {
            *b = SBOX[*b as usize];
        }
    }
    fn shift_rows(s: &mut [u8; 16]) {
        // state laid out column-major; row r elements are indices r, r+4, ...
        let mut t = [0u8; 16];
        for c in 0..4 {
            for r in 0..4 {
                t[c * 4 + r] = s[((c + r) % 4) * 4 + r];
            }
        }
        *s = t;
    }
    fn mix_columns(s: &mut [u8; 16]) {
        for c in 0..4 {
            let col = &mut s[c * 4..c * 4 + 4];
            let a = [col[0], col[1], col[2], col[3]];
            let a2 = [xtime(a[0]), xtime(a[1]), xtime(a[2]), xtime(a[3])];
            col[0] = a2[0] ^ a[1] ^ xtime(a[1]) ^ a[2] ^ a[3];
            col[1] = a[0] ^ a2[1] ^ a[2] ^ xtime(a[2]) ^ a[3];
            col[2] = a[0] ^ a[1] ^ a2[2] ^ a[3] ^ xtime(a[3]);
            col[3] = xtime(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ a2[3];
        }
    }

    add_round_key(&mut s, &round_keys[0]);
    for rk in round_keys.iter().take(10).skip(1) {
        sub_bytes(&mut s);
        shift_rows(&mut s);
        mix_columns(&mut s);
        add_round_key(&mut s, rk);
    }
    sub_bytes(&mut s);
    shift_rows(&mut s);
    add_round_key(&mut s, &round_keys[10]);
    s
}

/// AES-CMAC over `data` under `key` ([RFC 4493]); returns the 16-byte tag.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // AES-128 block cipher primitive
pub fn aes128_cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    const ZERO: [u8; 16] = [0; 16];
    let l = aes128_encrypt_block(key, &ZERO);

    // Subkeys K1/K2 via doubling on GF(2^128).
    fn dbl(b: [u8; 16]) -> [u8; 16] {
        let carry = b[0] >> 7;
        let mut out = [0u8; 16];
        // Big-endian array: left shift pulls each byte's incoming bit from
        // the NEXT byte's MSB; the shifted-out bit selects the 0x87
        // reduction term applied to the LAST byte.
        for i in 0..16 {
            let hi = if i == 15 { 0 } else { b[i + 1] >> 7 };
            out[i] = (b[i] << 1) | hi;
        }
        if carry != 0 {
            out[15] ^= 0x87;
        }
        out
    }
    let k1 = dbl(l);
    let k2 = dbl(k1);

    // An empty message counts as one all-zero complete block ([RFC 4493]
    // step 3), so it uses K1 like any other whole final block.
    let n = data.len().div_ceil(16).max(1);
    let complete = data.len().is_multiple_of(16);

    let mut last_block = [0u8; 16];
    if complete && !data.is_empty() {
        let start = (n - 1) * 16;
        last_block.copy_from_slice(&data[start..]);
        for i in 0..16 {
            last_block[i] ^= k1[i];
        }
    } else {
        // Empty or partial final block: 10* padding then K2.
        let start = if data.is_empty() { 0 } else { (n - 1) * 16 };
        last_block[..data.len() - start].copy_from_slice(&data[start..]);
        last_block[data.len() - start] = 0x80;
        for i in 0..16 {
            last_block[i] ^= k2[i];
        }
    }

    let mut x = ZERO;
    for chunk_start in (0..n - 1).map(|i| i * 16) {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&data[chunk_start..chunk_start + 16]);
        for i in 0..16 {
            x[i] ^= blk[i];
        }
        x = aes128_encrypt_block(key, &x);
    }
    for i in 0..16 {
        x[i] ^= last_block[i];
    }
    aes128_encrypt_block(key, &x)
}

