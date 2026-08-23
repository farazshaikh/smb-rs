//! Directory enumeration entry encoding for FIND_FIRST2/FIND_NEXT2 replies
//! ([MS-SMB] §2.2.8.1 information levels).

use smb_proto::types::FileTime;

/// Neutral directory-entry input for the encoder (kept free of storage-layer
/// types so the protocol crate stays self-contained).
#[derive(Debug, Clone)]
pub struct FindEntry {
    /// File name as presented to clients.
    pub name: String,
    /// Metadata snapshot.
    pub meta: crate::query::QueryMeta,
}

/// Fixed portion size per level, matching the fields written below.
const fn fixed_size(level: u16) -> usize {
    match level {
        // NextEntryOffset + FileIndex + 4×FILETIME + EOF + Alloc + Attrs
        // + NameLength ([MS-CIFS] §2.2.8.1.2).
        crate::find_level::DIRECTORY => 64,
        // …+ EaSize + Reserved ([MS-CIFS] §2.2.8.1.3).
        crate::find_level::FULL => 68,
        // …+ EaSize + ShortNameLen + Reserved + ShortName[12]
        // ([MS-CIFS] §2.2.8.1.7).
        crate::find_level::BOTH => 94,
        // NextEntryOffset + FileIndex + NameLength ([MS-CIFS] §2.2.8.1.4).
        crate::find_level::NAMES => 12,
        // DOS form incl. resume key ([MS-CIFS] §2.2.8.1.1).
        crate::find_level::STANDARD => 31,
        _ => 94,
    }
}

/// Encode one entry's fixed fields after its NextEntryOffset slot.
fn push_fixed(buf: &mut Vec<u8>, level: u16, m: &crate::query::QueryMeta, name_len: usize) {
    match level {
        crate::find_level::STANDARD => {
            // Resume-key slot doubles as FileIndex placeholder.
            buf.extend_from_slice(&0u32.to_le_bytes());
            for t in &m.times[..3] {
                let ft = FileTime(*t);
                let (secs, _) = ft.to_unix();
                buf.extend_from_slice(&(secs as u32).to_le_bytes());
            }
            buf.extend_from_slice(&(m.eof as u32).to_le_bytes());
            buf.extend_from_slice(&(m.alloc as u32).to_le_bytes());
            buf.extend_from_slice(&m.attrs.0.to_le_bytes());
            buf.push(name_len as u8);
        }
        crate::find_level::NAMES => {
            buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
            buf.extend_from_slice(&(name_len as u32).to_le_bytes());
        }
        crate::find_level::DIRECTORY => {
            buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
            for t in &m.times {
                buf.extend_from_slice(&t.to_le_bytes());
            }
            buf.extend_from_slice(&m.eof.to_le_bytes());
            buf.extend_from_slice(&m.alloc.to_le_bytes());
            buf.extend_from_slice(&m.attrs.0.to_le_bytes());
            buf.extend_from_slice(&(name_len as u32).to_le_bytes());
        }
        _ => {
            // FULL / BOTH
            buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
            for t in &m.times {
                buf.extend_from_slice(&t.to_le_bytes());
            }
            buf.extend_from_slice(&m.eof.to_le_bytes());
            buf.extend_from_slice(&m.alloc.to_le_bytes());
            buf.extend_from_slice(&m.attrs.0.to_le_bytes());
            buf.extend_from_slice(&(name_len as u32).to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            if level == crate::find_level::BOTH {
                buf.push(0); // ShortNameLength
                buf.push(0); // Reserved
                buf.extend_from_slice(&[0u8; 24]); // ShortName slot
            }
        }
    }
}

/// Encode `entries` into the chained NextEntryOffset form used by
/// FIND_FIRST2/NEXT2 responses. Returns the buffer plus the offset of the
/// last entry (`LastNameOffset`).
///
/// The final entry carries `NextEntryOffset == 0`; intermediate strides are
/// 4-byte aligned as clients require. Names are UTF-16LE when the client
/// negotiated Unicode, else OEM bytes.
pub fn encode_entries(
    entries: &[FindEntry],
    level: u16,
    unicode: bool,
) -> (Vec<u8>, Option<usize>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut last_off = None;

    for (i, e) in entries.iter().enumerate() {
        let start = buf.len();
        let m = &e.meta;
        let name_bytes: Vec<u8> = if unicode {
            let mut v = Vec::with_capacity(e.name.len() * 2);
            for u in e.name.encode_utf16() {
                v.extend_from_slice(&u.to_le_bytes());
            }
            v
        } else {
            e.name.as_bytes().to_vec()
        };

        // Reserve the NextEntryOffset slot; patched once the stride is known.
        let next_pos = buf.len();
        buf.extend_from_slice(&0u32.to_le_bytes());

        push_fixed(&mut buf, level, m, name_bytes.len());

        // DOS-standard records carry a trailing NUL after the name and are
        // byte-packed; NT levels pad to a 4-byte boundary.
        buf.extend_from_slice(&name_bytes);
        if level == crate::find_level::STANDARD {
            buf.push(0);
        }

        let stride = buf.len() - start;
        if i + 1 < entries.len() {
            let padded = (stride + 3) & !3usize;
            while buf.len() < start + padded {
                buf.push(0);
            }
            let next = (buf.len() - start) as u32;
            buf[next_pos..next_pos + 4].copy_from_slice(&next.to_le_bytes());
        }
        last_off = Some(start);
    }
    (buf, last_off)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::QueryMeta;

    fn mk(n: &str) -> FindEntry {
        FindEntry {
            name: n.into(),
            meta: QueryMeta {
                times: [1, 2, 3, 4],
                attrs: smb_proto::types::AttrFlags(0x20),
                eof: 19,
                alloc: 4096,
                is_dir: false,
            },
        }
    }

    fn next_at(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }

    #[test]
    fn both_level_chain_is_consistent() {
        let entries = vec![mk("a.txt"), mk("b.txt")];
        let (buf, _) = encode_entries(&entries, crate::find_level::BOTH, true);

        // Walk the NextEntryOffset chain: strides must be >= fixed size and
        // land on the next entry until the terminator (0) on the LAST entry.
        let mut off = 0usize;
        let mut count = 0;
        loop {
            assert!(off + 4 <= buf.len(), "chain walked past end");
            let next = next_at(&buf, off);
            if next == 0 {
                break;
            }
            assert!(next >= 94, "stride smaller than BOTH header");
            count += 1;
            off += next as usize;
        }
        count += 1; // terminator entry itself
        assert_eq!(count, entries.len(), "every entry must be reachable");
    }

    #[test]
    fn final_entry_has_zero_next_and_names_decode() {
        let entries = vec![mk("alpha"), mk("beta"), mk("gamma")];
        let levels = [
            crate::find_level::DIRECTORY,
            crate::find_level::FULL,
            crate::find_level::BOTH,
            crate::find_level::NAMES,
        ];
        for level in levels {
            let fixed = fixed_size(level);
            let (buf, last) =
                encode_entries(&entries, level, true);
            let mut off = 0usize;
            for e in &entries {
                let next = next_at(&buf, off);
                let expect_units: Vec<u8> = e.name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                // FileNameLength position differs per level: NT levels with
                // an EaSize field keep it before that trailing u32; the DOS
                // form uses a single length byte.
                let namelen = match level {
                    crate::find_level::FULL => u32::from_le_bytes(
                        buf[off + fixed - 8..off + fixed - 4].try_into().unwrap(),
                    ),
                    crate::find_level::BOTH => u32::from_le_bytes(
                        buf[off + fixed - 34..off + fixed - 30].try_into().unwrap(),
                    ),
                    crate::find_level::STANDARD => buf[off + fixed - 1] as u32,
                    _ => {
                        u32::from_le_bytes(buf[off + fixed - 4..off + fixed].try_into().unwrap())
                    }
                };
                assert_eq!(namelen as usize, expect_units.len(), "level {level:#x}");
                assert_eq!(
                    &buf[off + fixed..off + fixed + expect_units.len()],
                    &expect_units[..],
                    "level {level:#x}"
                );
                if off == last.unwrap() {
                    assert_eq!(next, 0, "last entry must terminate the chain");
                } else {
                    assert_eq!(next as usize % 4, 0, "strides must stay aligned");
                    off += next as usize;
                }
            }
        }
    }
}
