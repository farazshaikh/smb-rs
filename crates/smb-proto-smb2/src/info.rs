//! SMB2 information-level payload codecs ([MS-SMB2] §2.2.37/§2.2.39 with
//! [MS-FSCC] §2.4/§2.5/§2.6 structures).

use smb_proto::buf::Writer;

/// FileInformationClass values ([MS-FSCC] §2.4).
pub mod file_class {
    /// FILE_DIRECTORY_INFORMATION (find only).
    pub const DIRECTORY: u8 = 0x01;
    /// FILE_FULL_DIRECTORY_INFORMATION (find only).
    pub const FULL_DIRECTORY: u8 = 0x02;
    /// FILE_BOTH_DIRECTORY_INFORMATION (find only).
    pub const BOTH_DIRECTORY: u8 = 0x03;
    /// FileRenameInformation.
    pub const RENAME: u8 = 0x0A;
    /// FileDispositionInformation.
    pub const DISPOSITION: u8 = 0x0D;
    /// FileAllocationInformation.
    pub const ALLOCATION: u8 = 0x13;
    /// FileEndOfFileInformation.
    pub const END_OF_FILE: u8 = 0x14;
    /// FileBasicInformation.
    pub const BASIC: u8 = 0x04;
    /// FileStandardInformation.
    pub const STANDARD: u8 = 0x05;
    /// FileInternalInformation.
    pub const INTERNAL: u8 = 0x06;
    /// FileEaInformation.
    pub const EA: u8 = 0x07;
    /// FileAccessInformation.
    pub const ACCESS: u8 = 0x08;
    /// FileNameInformation.
    pub const NAME: u8 = 0x09;
    /// FileModeInformation.
    pub const MODE: u8 = 0x10;
    /// FileAlignmentInformation.
    pub const ALIGNMENT: u8 = 0x11;
    /// FileAllInformation.
    pub const ALL: u8 = 0x12;
    /// FileStreamInformation ([MS-FSCC] §2.4.40).
    pub const STREAM: u8 = 0x16;
    /// FilePositionInformation.
    pub const POSITION: u8 = 0x0E;
    /// FileNetworkOpenInformation.
    pub const NETWORK_OPEN: u8 = 0x22;
    /// FileAttributeTagInformation.
    pub const ATTRIBUTE_TAG: u8 = 0x23;
}

/// FsInformationClass values ([MS-FSCC] §2.5).
pub mod fs_class {
    /// FileFsVolumeInformation.
    pub const VOLUME: u8 = 0x01;
    /// FileFsSizeInformation.
    pub const SIZE: u8 = 0x03;
    /// FileFsDeviceInformation.
    pub const DEVICE: u8 = 0x04;
    /// FileFsAttributeInformation.
    pub const ATTRIBUTE: u8 = 0x05;
    /// FileFsFullSizeInformation.
    pub const FULL_SIZE: u8 = 0x07;
}

/// Directory enumeration classes beyond [MS-FSCC] §2.4 basics
/// ([MS-SMB2] §2.2.33.2 / Windows FILE_INFO_FROM_CLASS numbers).
pub mod find_class {
    /// FILE_NAMES_INFORMATION.
    pub const NAMES: u8 = 0x0C;
    /// FILE_ID_BOTH_DIRECTORY_INFORMATION.
    pub const ID_BOTH_DIRECTORY: u8 = 37;
    /// FILE_ID_FULL_DIRECTORY_INFORMATION.
    pub const ID_FULL_DIRECTORY: u8 = 38;
}

/// Neutral metadata snapshot fed to the encoders below.
#[derive(Debug, Clone, Default)]
pub struct QueryMeta {
    /// Creation / last-access / last-write / change FILETIMEs (raw NT).
    pub times: [u64; 4],
    /// Attribute flags.
    pub attrs: u32,
    /// End of file in bytes.
    pub eof: u64,
    /// Allocation size in bytes.
    pub alloc: u64,
    /// True when the object is a directory.
    pub is_dir: bool,
}

impl QueryMeta {
    /// Snapshot from a VFS metadata struct.
    pub fn from_vfs(m: &smb_vfs::FileMeta) -> QueryMeta {
        QueryMeta {
            times: [m.times[0].0, m.times[1].0, m.times[2].0, m.times[3].0],
            attrs: m.attrs.0,
            eof: if m.is_dir { 0 } else { m.eof },
            alloc: m.alloc,
            is_dir: m.is_dir,
        }
    }
}

/// Access mask reported by ACCESS/ALL levels for handles opened on this
/// server (read+write generic set).
pub const GENERIC_RW_ACCESS: u32 = 0x0012_0089 | 0x0000_0016;

fn push_utf16_len(d: &mut Writer, s: &str) {
    let units: Vec<u16> = s.encode_utf16().collect();
    d.push_u32((units.len() * 2) as u32);
    for u in units {
        d.push_u16(u);
    }
}

fn push_times(d: &mut Writer, times: &[u64; 4]) {
    for t in times {
        d.push_u64(*t);
    }
}

/// Encode a QUERY_INFO file payload for `class` from neutral metadata.
///
/// `name` is the final path component (NAME level). Returns `None` for
/// classes this server does not implement; callers map that to
/// `STATUS_INVALID_PARAMETER` or `NOT_SUPPORTED`.
pub fn encode_file_info(class: u8, m: &QueryMeta, name: &str) -> Option<Vec<u8>> {
    let mut d = Writer::new(0);
    match class {
        file_class::BASIC => {
            push_times(&mut d, &m.times);
            d.raw(&m.attrs.to_le_bytes());
            d.push_u32(0); // Reserved: FileBasicInformation is 40 bytes ([MS-FSCC] §2.4.7)
        }
        file_class::STANDARD => {
            d.push_u64(m.alloc);
            d.push_u64(m.eof);
            d.push_u32(1); // NumberOfLinks
            d.push(0); // DeletePending
            d.push(m.is_dir as u8);
            d.push_u16(0); // Reserved
        }
        file_class::INTERNAL => {
            d.push_u64(0); // IndexNumber placeholder
        }
        file_class::EA => {
            d.push_u32(0); // EaSize
        }
        file_class::ACCESS => {
            d.raw(&GENERIC_RW_ACCESS.to_le_bytes());
        }
        file_class::NAME => push_utf16_len(&mut d, name),
        file_class::MODE => {
            d.raw(&0u32.to_le_bytes());
        }
        file_class::ALIGNMENT => {
            d.raw(&0u32.to_le_bytes());
        }
        file_class::POSITION => {
            d.push_u64(0); // CurrentByteOffset
        }
        file_class::ATTRIBUTE_TAG => {
            d.raw(&m.attrs.to_le_bytes());
            d.push_u32(0); // ReparseTag
        }
        file_class::NETWORK_OPEN => {
            push_times(&mut d, &m.times);
            d.push_u64(m.alloc);
            d.push_u64(m.eof);
            d.raw(&m.attrs.to_le_bytes());
        }
        file_class::ALL => {
            // Embedded FSCC structures are 8-byte aligned within the
            // composite ([MS-FSCC] §2.4.1):
            // Basic(40) Standard(24) Internal(8) Ea(4) Access(4)
            // Position(8) Mode(4) Alignment(4) FileName(variable).
            push_times(&mut d, &m.times); // 0..32
            d.raw(&m.attrs.to_le_bytes()); // 32..36
            d.push_u32(0); // pad to Basic's 40-byte footprint
            d.push_u64(m.alloc); // 40
            d.push_u64(m.eof); // 48
            d.push_u32(1); // links 56
            d.push(0); // delete pending 60
            d.push(m.is_dir as u8); // 61
            d.push_u16(0); // reserved 62
            d.push_u64(0); // index number 64
            d.push_u32(0); // ea size 72
            d.raw(&GENERIC_RW_ACCESS.to_le_bytes()); // access 76
            d.push_u64(0); // current byte offset 80
            d.push_u32(0); // mode 88
            d.push_u32(0); // alignment requirement 92
            // FileNameInformation: Windows returns FileNameLength 0 here
            // ([MS-SMB2] §3.3.5.20.1 / MS-FSCC §2.4.7 via a handle query).
            d.push_u32(0); // FileNameLength 96
        }
        _ => return None,
    }
    Some(d.into_inner())
}

/// Encode a FILE_STREAM_INFORMATION chain ([MS-FSCC] §2.4.40) from a list of
/// `(stream_name, size)` pairs. Names are the full SMB stream syntax, e.g.
/// `::$DATA` for the default data stream or `:Zone.Identifier:$DATA` for an
/// alternate data stream. An empty list yields an empty buffer (no streams).
pub fn encode_stream_info(streams: &[(String, u64)]) -> Vec<u8> {
    let mut d = Writer::new(0);
    for (i, (name, size)) in streams.iter().enumerate() {
        let units: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = units.len() * 2;
        // Entry = 24-byte fixed part + name, padded to an 8-byte boundary.
        let entry_len = 24 + name_bytes;
        let padded = entry_len.next_multiple_of(8);
        let next = if i + 1 == streams.len() { 0 } else { padded };
        d.push_u32(next as u32); // NextEntryOffset
        d.push_u32(name_bytes as u32); // StreamNameLength
        d.push_u64(*size); // StreamSize
        d.push_u64(*size); // StreamAllocationSize
        for u in units {
            d.push_u16(u);
        }
        d.raw(&vec![0u8; padded - entry_len]);
    }
    d.into_inner()
}

/// Encode a QUERY_INFO filesystem payload for `class`.
pub fn encode_fs_info(class: u8) -> Option<Vec<u8>> {
    let mut d = Writer::new(0);
    match class {
        fs_class::VOLUME => {
            d.push_u64(smb_proto::types::FileTime::now().0); // CreationTime
            d.push_u64(0x2023_0405_0607_0809); // VolumeSerialNumber
            push_utf16_len(&mut d, "RUSTSMB"); // VolumeLabelLength + label
        }
        fs_class::SIZE | fs_class::FULL_SIZE => {
            d.push_u64(34_464); // TotalAllocationUnits
            if class == fs_class::FULL_SIZE {
                d.push_u64(17_232); // AvailableAllocationUnits (caller)
            }
            d.push_u64(17_232); // AvailableAllocationUnits
            d.push_u32(50); // SectorsPerAllocationUnit
            d.push_u32(1000); // BytesPerSector
        }
        fs_class::DEVICE => {
            d.push_u32(7); // DeviceType: FILE_DEVICE_DISK
            d.push_u32(0x0002_0020); // Characteristics: mounted+removable-off
        }
        fs_class::ATTRIBUTE => {
            d.push_u32(0x0007_0007); // FileSystemAttributes:
                                     // case-preserved|case-sensitive|persistent-acls|unicode
            d.push_u32(255); // MaximumComponentNameLength
            push_utf16_len(&mut d, "NTFS");
        }
        _ => return None,
    }
    Some(d.into_inner())
}

// ---------------- SET_INFO decoding ----------------

/// Decode SET_INFO `buffer` into a neutral [`smb_vfs::SetOp`] where the
/// operation maps onto one; `Ok(None)` means accepted-but-ignored (e.g.
/// position), and errors mean an unsupported/malformed class.
pub fn decode_set_file_op(class: u8, buf: &[u8]) -> Result<Option<smb_vfs::SetOp>, ()> {
    let r64 = |o: usize| -> u64 {
        buf.get(o..o + 8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
            .unwrap_or(0)
    };
    match class {
        file_class::BASIC => {
            // FileBasicInformation ([MS-FSCC] §2.4.7): CreationTime(0),
            // LastAccessTime(8), LastWriteTime(16), ChangeTime(24).
            let ft = |v: u64| (v != 0 && v != u64::MAX).then_some(smb_proto::types::FileTime(v));
            Ok(Some(smb_vfs::SetOp::Basic {
                access: ft(r64(8)),
                write: ft(r64(16)),
            }))
        }
        file_class::END_OF_FILE => Ok(Some(smb_vfs::SetOp::EndOfFile(r64(0)))),
        file_class::ALLOCATION => Ok(Some(smb_vfs::SetOp::Allocation(r64(0)))),
        file_class::DISPOSITION => Ok(Some(smb_vfs::SetOp::Disposition {
            delete: buf.first().copied().unwrap_or(0) != 0,
        })),
        file_class::RENAME => {
            // ReplaceIfExists(1)+Reserved(3) RootDirectory(8) NameLen(4) then
            // UTF-16LE name ([MS-FSCC] §2.4.34.1).
            if buf.len() < 20 {
                return Err(());
            }
            let replace = buf.first().copied().unwrap_or(0) != 0;
            let len =
                u32::from_le_bytes(buf[16..20].try_into().map_err(|_| ())?) as usize;
            let raw = buf.get(20..(20 + len).min(buf.len())).ok_or(())?;
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| c[0] as u16 | ((c[1] as u16) << 8))
                .collect();
            let name = String::from_utf16_lossy(&units).replace('/', "\\");
            Ok(Some(smb_vfs::SetOp::Rename { replace_if_exists: replace, name }))
        }
        file_class::POSITION => Ok(None), // advisory only
        _ => Err(()),
    }
}

// ---------------- Directory enumeration encoding ----------------

/// One directory entry to encode.
#[derive(Debug, Clone)]
pub struct FindEntry {
    /// Final path component.
    pub name: String,
    /// Metadata snapshot.
    pub meta: QueryMeta,
}

/// Write the fixed fields of one entry after the NextEntryOffset slot.
fn push_find_fixed(buf: &mut Vec<u8>, class: u8, m: &QueryMeta, name: &str, name_len: usize) {
    if class == find_class::NAMES {
        // FILE_NAMES_INFORMATION: Next(4) FileIndex(4) NameLen(4).
        buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
        buf.extend_from_slice(&(name_len as u32).to_le_bytes());
        return;
    }
    buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
    for t in &m.times {
        buf.extend_from_slice(&t.to_le_bytes());
    }
    buf.extend_from_slice(&m.eof.to_le_bytes());
    buf.extend_from_slice(&m.alloc.to_le_bytes());
    buf.extend_from_slice(&m.attrs.to_le_bytes());
    buf.extend_from_slice(&(name_len as u32).to_le_bytes());
    match class {
        file_class::FULL_DIRECTORY => {
            buf.extend_from_slice(&0u32.to_le_bytes()); // EaSize
        }
        file_class::BOTH_DIRECTORY => {
            buf.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            push_short_name(buf, name);
        }
        find_class::ID_FULL_DIRECTORY => {
            buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved
            buf.extend_from_slice(&0u64.to_le_bytes()); // FileId
        }
        find_class::ID_BOTH_DIRECTORY => {
            buf.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            push_short_name(buf, name);
            buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
            buf.extend_from_slice(&0u64.to_le_bytes()); // FileId
        }
        _ => {}
    }
}

/// Encode the 8.3 ShortName field (ShortNameLength(1) Reserved(1) ShortName(24))
/// of a BOTH_DIRECTORY entry, generating a short name for non-8.3 long names.
fn push_short_name(buf: &mut Vec<u8>, name: &str) {
    let short = short_name_8_3(name);
    let units: Vec<u16> = short.encode_utf16().collect();
    buf.push((units.len() * 2) as u8); // ShortNameLength (bytes)
    buf.push(0); // Reserved
    let mut field = [0u8; 24];
    for (i, u) in units.iter().take(12).enumerate() {
        field[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }
    buf.extend_from_slice(&field);
}

/// Characters permitted (besides A-Z 0-9) in a DOS 8.3 name.
const SHORT_NAME_SYMBOLS: &str = "!#$%&'()-@^_`{}~";

/// Generate a DOS 8.3 short name for a long name ([MS-FSCC] §2.1.5.2.1 style):
/// uppercased, invalid characters dropped, base truncated to 6 plus `~1`, and a
/// 3-character extension. Returns `""` when `name` is already a valid 8.3 name
/// (Windows then reports no short name).
pub fn short_name_8_3(name: &str) -> String {
    if is_valid_8_3(name) {
        return String::new();
    }
    let (base, ext) = match name.rsplit_once('.') {
        Some((b, e)) if !b.is_empty() => (b, e),
        _ => (name, ""),
    };
    let clean = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || SHORT_NAME_SYMBOLS.contains(*c))
            .map(|c| c.to_ascii_uppercase())
            .collect()
    };
    let b: String = clean(base).chars().take(6).collect();
    let e: String = clean(ext).chars().take(3).collect();
    let b = if b.is_empty() { "_".to_string() } else { b };
    if e.is_empty() {
        format!("{b}~1")
    } else {
        format!("{b}~1.{e}")
    }
}

/// Whether `name` already fits the 8.3 form (case-insensitively), in which case
/// no short name is generated for it.
fn is_valid_8_3(name: &str) -> bool {
    let (base, ext) = match name.rsplit_once('.') {
        Some((b, e)) => (b, e),
        None => (name, ""),
    };
    let ok = |s: &str, max: usize| -> bool {
        s.len() <= max
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || SHORT_NAME_SYMBOLS.contains(c))
    };
    !base.is_empty() && ok(base, 8) && ok(ext, 3)
}

/// Encode directory entries into the NextEntryOffset-chained form used by
/// QUERY_DIRECTORY responses. The final entry terminates with offset 0 and
/// intermediate strides are 8-byte aligned ([MS-FSCC] §2.4 requires 8-byte
/// alignment for SMB2 clients).
pub fn encode_find_entries(entries: &[FindEntry], class: u8) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let start = buf.len();
        let mut name_bytes = Vec::with_capacity(e.name.len() * 2);
        for u in e.name.encode_utf16() {
            name_bytes.extend_from_slice(&u.to_le_bytes());
        }

        let next_pos = buf.len();
        buf.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset slot

        push_find_fixed(&mut buf, class, &e.meta, &e.name, name_bytes.len());
        buf.extend_from_slice(&name_bytes);

        let stride = buf.len() - start;
        if i + 1 < entries.len() {
            let aligned = (stride + 7) & !7usize;
            while buf.len() < start + aligned {
                buf.push(0);
            }
            let next = (buf.len() - start) as u32;
            buf[next_pos..next_pos + 4].copy_from_slice(&next.to_le_bytes());
        }
    }
    buf
}

#[cfg(test)]
mod stream_info_tests {
    use super::*;

    #[test]
    fn encodes_default_plus_ads_chain() {
        let streams = vec![
            ("::$DATA".to_string(), 9u64),
            (":Zone.Identifier:$DATA".to_string(), 26u64),
        ];
        let buf = encode_stream_info(&streams);
        // First entry: NextEntryOffset != 0, name "::$DATA" (7 UTF-16 units).
        let next0 = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_ne!(next0, 0, "first entry links to the second");
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 14, "::$DATA name bytes");
        assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 9, "default stream size");
        assert_eq!(next0 % 8, 0, "entries are 8-byte aligned");
        // Last entry's NextEntryOffset is zero.
        let last = next0 as usize;
        assert_eq!(u32::from_le_bytes(buf[last..last + 4].try_into().unwrap()), 0, "chain terminates");
    }

    #[test]
    fn empty_list_is_empty_buffer() {
        assert!(encode_stream_info(&[]).is_empty());
    }
}

#[cfg(test)]
mod short_name_tests {
    use super::*;

    #[test]
    fn generates_8_3_for_long_names() {
        assert_eq!(short_name_8_3("LongFileName.txtx"), "LONGFI~1.TXT");
        assert_eq!(short_name_8_3("noext_longname"), "NOEXT_~1");
        // Already a valid 8.3 name yields no short name.
        assert_eq!(short_name_8_3("READ.ME"), "");
        assert_eq!(short_name_8_3("A.B"), "");
    }
}
