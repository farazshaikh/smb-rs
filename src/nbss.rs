// NetBIOS session service framing (RFC 1002) over a TCP stream.

use std::io::{self, Read, Write};

pub const NBSS_SESSION_MESSAGE: u8 = 0x00;

pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = payload.len();
    if len > 0x1_FFFE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut hdr = [0u8; 4];
    hdr[0] = NBSS_SESSION_MESSAGE;
    hdr[1] = 0;
    hdr[2] = (len >> 8) as u8;
    hdr[3] = (len & 0xFF) as u8;
    w.write_all(&hdr)?;
    w.write_all(payload)?;
    w.flush()
}

pub enum Frame {
    /// Session message carrying an SMB PDU.
    Message(Vec<u8>),
    /// RFC 1002 session request (type 0x81).
    SessionRequest,
    /// RFC 1002 session keepalive (type 0x85).
    Keepalive,
}

fn read_nbss_header<R: Read>(r: &mut R) -> io::Result<Option<[u8; 4]>> {
    let mut hdr = [0u8; 4];
    match r.read_exact(&mut hdr) {
        Ok(()) => Ok(Some(hdr)),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => {
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// Read one NBSS frame; Ok(None) on clean EOF between frames.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Frame>> {
    let hdr = match read_nbss_header(r)? {
        Some(h) => h,
        None => return Ok(None),
    };
    let mtype = hdr[0];
    if mtype == 0x81 {
        // Consume and discard the called/calling names, then signal caller.
        let _len =
            ((hdr[1] as usize & 0x01) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
        if _len > 0 && _len < 0x2000 {
            let mut junk = vec![0u8; _len];
            r.read_exact(&mut junk)?;
        }
        return Ok(Some(Frame::SessionRequest));
    }
    if mtype == 0x85 {
        return Ok(Some(Frame::Keepalive));
    }
    if mtype != NBSS_SESSION_MESSAGE {
        // Unknown control type: drain and ignore.
        return Ok(Some(Frame::Keepalive));
    }
    // 17-bit length: flags bit0 extends length.
    let len = ((hdr[1] as usize & 0x01) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
    if len > 0x20_000 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized frame"));
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        match r.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Ok(None)
            }
            Err(e) => return Err(e),
        }
    }
    Ok(Some(Frame::Message(buf)))
}
