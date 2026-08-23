//! QUERY_INFORMATION payload encoders for the information levels
//! ([MS-SMB] §2.2.8.2–4).

use smb_proto::buf::Writer;
use smb_proto::types::AttrFlags;

/// Neutral metadata snapshot used by query payload encoders.
#[derive(Debug, Clone, Default)]
pub struct QueryMeta {
    /// Creation / access / write / change FILETIMEs.
    pub times: [u64; 4],
    /// Attribute flags.
    pub attrs: AttrFlags,
    /// End-of-file size.
    pub eof: u64,
    /// Allocation size.
    pub alloc: u64,
    /// Directory flag.
    pub is_dir: bool,
}

/// Encode a QUERY_PATH/FILE information payload for `level` from neutral
/// metadata. Returns `Err(())` for levels this server does not implement —
/// callers translate that to `INVALID_PARAMETER`.
///
/// `name` is required by the NAME/ALT_NAME levels.
pub fn encode_payload(
    level: u16,
    m: &QueryMeta,
    name: &str,
) -> Result<Vec<u8>, ()> {
    let times = &m.times;
    let eof = if m.is_dir { 0 } else { m.eof };
    let alloc = ((eof + 4095) / 4096) * 4096;

    let mut d = Writer::new(0);
    match level {
        0x004 | 0x1004 | 0x101 => {
            // BASIC: creation, access, write, change + attributes.
            for t in &times[..3] {
                d.push_u64(*t);
            }
            d.push_u64(times[3]);
            d.raw(&m.attrs.0.to_le_bytes());
        }
        0x005 => {
            // STANDARD (22-byte non-passthrough form).
            d.push_u64(alloc);
            d.push_u64(eof);
            d.push_u32(1); // links
            d.push(if m.attrs.0 & 0x1 != 0 { 1 } else { 0 }); // delete pending
            d.push(m.is_dir as u8);
        }
        0x1005 => {
            // STANDARD pass-through (24-byte form with reserved word).
            d.push_u64(alloc);
            d.push_u64(eof);
            d.push_u32(1); // links
            d.push(0); // delete pending
            d.push(m.is_dir as u8);
            d.push_u16(0); // reserved
        }
        0x006 | 0x1007 => {
            d.push_u32(0); // EA size
        }
        0x007 => {
            d.push_u32(4); // all-EA list length
            d.push_u32(0); // full list length
        }
        0x1006 => {
            d.push_u64(0); // index number placeholder
        }
        0x1008 => {
            d.push_u32(0x0012_0089 | 0x0000_0016); // read+write access flags
        }
        0x1009 | 0x1015 => {
            let units: Vec<u16> = name.encode_utf16().collect();
            d.push_u32((units.len() * 2) as u32);
            for u in units {
                d.push_u16(u);
            }
        }
        0x100B | 0x103 => {
            d.push_u64(alloc);
        }
        0x100C | 0x104 => {
            d.push_u64(eof);
        }
        0x100D => {
            d.push(0);
        }
        0x1012 => {
            for t in times.iter() {
                d.push_u64(*t);
            }
            d.push_u64(alloc);
            d.push_u64(eof);
            d.push_u32(1); // links
            d.push(0); // delete pending
            d.push(m.is_dir as u8);
            d.push_u16(0); // reserved
            d.push_u32(0); // EA size
            d.push_u32(0x0012_0089 | 0x16); // access flags
            d.push_u64(0); // current byte offset
            d.raw(&m.attrs.0.to_le_bytes());
        }
        0x010 | 0x1016 => {
            d.push_u32(0); // empty stream list
        }
        0x107 => {
            // Composite getattr: times, attrs, rsvd, alloc, eof, links,
            // del/dir flags, pad, index, namelen, name.
            for t in times.iter() {
                d.push_u64(*t);
            }
            d.raw(&m.attrs.0.to_le_bytes());
            d.push_u32(0); // reserved
            d.push_u64(alloc);
            d.push_u64(eof);
            d.push_u32(1); // links
            d.push(0); // delete pending
            d.push(m.is_dir as u8);
            d.push_u16(0); // pad
            d.push_u32(0); // index
            let units: Vec<u16> = name.encode_utf16().collect();
            d.push_u32((units.len() * 2) as u32);
            for u in units {
                d.push_u16(u);
            }
        }
        _ => return Err(()),
    }
    Ok(d.into_inner())
}
