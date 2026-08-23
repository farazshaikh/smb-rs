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

/// Fixed header size per level.
fn fixed_size(level: u16) -> usize {
    match level {
        crate::find_level::BOTH => 94,
        crate::find_level::FULL => 68,
        crate::find_level::DIRECTORY => 32,
        crate::find_level::NAMES => 12,
        crate::find_level::STANDARD => 27,
        _ => 94,
    }
}

/// Encode `entries` into the chained NextEntryOffset form used by
/// FIND_FIRST2/NEXT2 responses. Returns the buffer plus the offset of the
/// last entry (`LastNameOffset`).
///
/// Names are UTF-16LE when the client negotiated Unicode, else OEM bytes.
pub fn encode_entries(
    entries: &[FindEntry],
    level: u16,
    unicode: bool,
) -> (Vec<u8>, Option<usize>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut last_off = None;

    for e in entries {
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

        let fixed = fixed_size(level);
        let total = if level == crate::find_level::STANDARD {
            fixed + name_bytes.len() + 1
        } else {
            fixed + name_bytes.len()
        };
        let padded = (total + 3) & !3usize;

        buf.extend_from_slice(&(padded as u32).to_le_bytes()); // NextEntryOffset

        match level {
            crate::find_level::STANDARD => {
                buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
                for t in &m.times[..3] {
                    let ft = FileTime(*t);
                    let (secs, _) = ft.to_unix();
                    buf.extend_from_slice(&(secs as u32).to_le_bytes());
                }
                buf.extend_from_slice(&(m.eof as u32).to_le_bytes());
                buf.extend_from_slice(&(m.alloc as u32).to_le_bytes());
                buf.extend_from_slice(&m.attrs.0.to_le_bytes());
                buf.push(name_bytes.len() as u8);
                buf.extend_from_slice(&name_bytes);
            }
            crate::find_level::NAMES => {
                buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
                buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            }
            crate::find_level::DIRECTORY => {
                buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
                buf.extend_from_slice(&m.eof.to_le_bytes());
                buf.extend_from_slice(&m.alloc.to_le_bytes());
                buf.extend_from_slice(&m.attrs.0.to_le_bytes());
                buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            }
            _ => {
                // FULL / BOTH
                buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
                for t in &m.times {
                    buf.extend_from_slice(&(*t).to_le_bytes());
                }
                buf.extend_from_slice(&m.eof.to_le_bytes());
                buf.extend_from_slice(&m.alloc.to_le_bytes());
                buf.extend_from_slice(&m.attrs.0.to_le_bytes());
                buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(&0u32.to_le_bytes()); // EaSize
                if level == crate::find_level::BOTH {
                    buf.push(0); // ShortNameLength
                    buf.push(0); // Reserved
                    buf.extend_from_slice(&[0u8; 24]); // ShortName slot
                }
            }
        }
        buf.extend_from_slice(&name_bytes);
        while buf.len() < padded + start {
            buf.push(0);
        }
        last_off = Some(start);
    }
    (buf, last_off)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::QueryMeta;

    #[test]
    fn both_level_chain_is_consistent() {
        let mk = |n: &str| FindEntry {
            name: n.into(),
            meta: QueryMeta {
                times: [1, 2, 3, 4],
                attrs: smb_proto::types::AttrFlags(0x20),
                eof: 19,
                alloc: 4096,
                is_dir: false,
            },
        };
        let entries = vec![mk("a.txt"), mk("b.txt")];
        let (buf, _) = encode_entries(&entries, crate::find_level::BOTH, true);

        // Walk the NextEntryOffset chain; every stride must be >= fixed size
        // and land on the next entry until the terminator (0).
        let mut off = 0usize;
        let mut count = 0;
        loop {
            assert!(off + 4 <= buf.len(), "chain walked past end");
            let next = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            assert!(next == 0 || next >= 94, "stride smaller than BOTH header");
            count += 1;
            if next == 0 {
                break;
            }
            off += next;
        }
        assert_eq!(count, entries.len(), "every entry must be reachable");
    }
}
