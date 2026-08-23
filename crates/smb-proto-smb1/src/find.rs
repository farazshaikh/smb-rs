//! Directory enumeration entry encoding for FIND_FIRST2/FIND_NEXT2 replies
//! ([MS-SMB] §2.2.8.1 information levels).

use smb_proto::types::FileTime;
use smb_vfs::Entry;

/// Fixed header size per level.
fn fixed_size(level: u16) -> usize {
    match level {
        crate::find_level::BOTH => 94, // next4 idx4 times32 eof8 alloc8 attr4 nlen4 ea4 slen1 res1 short24
        crate::find_level::FULL => 68,
        crate::find_level::DIRECTORY => 32,
        crate::find_level::NAMES => 12,
        crate::find_level::STANDARD => 27,
        _ => 94,
    }
}

/// Encode `entries` into the chained NextEntryOffset form used by
/// TRANS2_FIND_FIRST2/NEXT2 responses. Returns the buffer plus the offset of
/// the last entry (for `LastNameOffset`).
///
/// Names are UTF-16LE when the client negotiated Unicode, otherwise OEM bytes.
pub fn encode_entries(
    entries: &[Entry],
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
        let total = match level {
            crate::find_level::STANDARD => fixed + name_bytes.len() + 1,
            _ => fixed + name_bytes.len(),
        };
        let padded = (total + 3) & !3usize;

        buf.extend_from_slice(&(padded as u32).to_le_bytes()); // NextEntryOffset

        match level {
            crate::find_level::STANDARD => {
                buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
                for t in &m.times[..3] {
                    let (secs, _) = smb_proto::types::filetime_to_unix(t.0);
                    buf.extend_from_slice(&(secs as u32).to_le_bytes());
                }
                buf.extend_from_slice(&(m.eof as u32).to_le_bytes());
                buf.extend_from_slice(&(m.alloc as u32).to_le_bytes());
                buf.extend_from_slice(&(m.attrs.0 as u16).to_le_bytes());
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
                    buf.extend_from_slice(&t.0.to_le_bytes());
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
    use crate::find_level;

    fn sample(name: &str) -> Entry {
        Entry {
            name: name.into(),
            meta: FileMeta {
                times: [FileTime(1), FileTime(2), FileTime(3), FileTime(4)],
                attrs: smb_proto::types::AttrFlags(smb_proto::types::AttrFlags::ARCHIVE),
                alloc: 4096,
                eof: 19,
                is_dir: false,
            },
        }
    }

    #[test]
    fn both_level_stride_is_consistent() {
        let entries = vec![sample("a.txt"), sample("b.txt")];
        let (buf, _) = encode_entries(&entries, find_level::BOTH, true);
        // Walk the chain.
        let mut off = 0usize;
        let mut count = 0;
        while off < buf.len() {
            let next =
                u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            assert!(next >= 94, "stride smaller than fixed header");
            if next == 0 {
                break;
            }
            off += next;
            count += 1;
        }
        assert_eq!(count, 1); // second entry reached via stride; chain walked once here
    }
}
