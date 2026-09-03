//! Core/LANMAN-era path commands ([MS-CIFS]): MKDIR, RMDIR, CHECK_DIRECTORY,
//! DELETE, RENAME, QUERY_INFORMATION and SET_INFORMATION.

use smb_server_proto::buf::Reader;

/// Read one NUL-terminated path string from the command's data area,
/// honouring the Unicode flag and BufferFormat `0x04` prefixes.
///
/// `data_base` is the absolute frame offset of `data[0]`.
pub fn read_path(req_data: &[u8], unicode: bool, data_base: usize) -> String {
    let mut rd = Reader::new(req_data, 0);
    if !req_data.is_empty() && req_data[0] == 0x04 {
        rd.skip(1);
    }
    rd.zstring(unicode, data_base)
}

/// Read the two NUL-terminated strings of a RENAME request.
pub fn read_two_paths(req_data: &[u8], unicode: bool, data_base: usize) -> (String, String) {
    let mut rd = Reader::new(req_data, 0);
    if (!req_data.is_empty() && req_data[0] == 0x04)
        || (unicode && !data_base.is_multiple_of(2) && !req_data.is_empty())
    {
        rd.skip(1);
    }
    let a = rd.zstring(unicode, data_base);
    if !rd.at_end() {
        // Realign for the second string.
        if unicode && (data_base + rd.pos()) & 1 != 0 {
            rd.skip(1);
        }
        if rd.pos() < req_data.len() && req_data[rd.pos()] == 0x04 {
            rd.skip(1);
        }
    }
    let b = rd.zstring(unicode, data_base + rd.pos());
    (a, b)
}

/// QUERY_INFORMATION (0x08) response: attributes, DOS write time, size.
#[derive(Debug)]
pub struct QueryInfoResp {
    /// Attribute flags.
    pub attrs: u16,
    /// Last-write time in DOS encoding.
    pub dos_time: u32,
    /// File size in bytes.
    pub size: u32,
}

impl QueryInfoResp {
    /// Encode the WC=10 parameter block.
    pub fn encode(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(20);
        p.extend_from_slice(&self.attrs.to_le_bytes());
        p.extend_from_slice(&self.dos_time.to_le_bytes());
        p.extend_from_slice(&self.size.to_le_bytes());
        p.extend_from_slice(&[0u8; 14]); // reserved
        p
    }
}

/// Parse a legacy DOS-encoded UTC time into Unix seconds
/// ([MS-DTYP] DOSDATE/TIME packing used by core protocol fields).
pub fn dos_time_to_unix(dos: u32) -> u64 {
    let date = dos >> 16;
    let time = dos & 0xffff;
    let year = 1980 + ((date >> 9) & 0x7f) as i64;
    let month = (date >> 5) & 0xf;
    let day = date & 0x1f;
    let hours = (time >> 11) & 0x1f;
    let minutes = (time >> 5) & 0x3f;
    let seconds = ((time & 0x1f) * 2) as i64;
    // Days since epoch via simple civil-date conversion.
    let days = days_from_civil(year, month.max(1) as u64, day.max(1) as u64);
    (days * 86400 + (hours as i64) * 3600 + (minutes as i64) * 60 + seconds) as u64
}

fn days_from_civil(y: i64, m: u64, d: u64) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}
