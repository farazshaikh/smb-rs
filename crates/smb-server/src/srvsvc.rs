//! srvsvc DCERPC endpoint over named pipes ([MS-RPCE] + [MS-SRVS]).
//!
//! Handles pipe open/close, WRITE/READ of DCERPC PDUs, and
//! NetShareEnumAll (opnum 15) responses for `smbclient -L`.

use std::collections::VecDeque;

use ms_ndr::NdrEncoder;

/// One advertised share for NetShareEnum level 1.
#[derive(Debug, Clone)]
pub struct ShareInfo {
    pub netname: String,
    pub shi_type: u32,
    pub remark: String,
}

/// A virtual named pipe bound to one open file id.
pub struct Pipe {
    pub name: String,
    inbound: Vec<u8>,
    outbound: VecDeque<Vec<u8>>,
}

impl Pipe {
    pub fn new(name: &str) -> Self {
        Self { name: name.to_lowercase(), inbound: Vec::new(), outbound: VecDeque::new() }
    }

    pub fn pending(&self) -> usize {
        self.outbound.front().map_or(0, |v| v.len())
    }

    pub fn take(&mut self, max: usize) -> Vec<u8> {
        match self.outbound.front_mut() {
            Some(msg) => {
                let n = msg.len().min(max);
                let out = msg.drain(..n).collect();
                if msg.is_empty() { self.outbound.pop_front(); }
                out
            }
            None => Vec::new(),
        }
    }

    pub fn on_write(&mut self, data: &[u8], shares: &[ShareInfo]) {
        self.inbound.extend_from_slice(data);
        loop {
            if self.inbound.len() < 16 { break; }
            let frag_len = u16::from_le_bytes([self.inbound[8], self.inbound[9]]) as usize;
            if self.inbound.len() < frag_len { break; }
            let pdu: Vec<u8> = self.inbound.drain(..frag_len).collect();
            let ptype = pdu[2];
            let call_id = u32::from_le_bytes([pdu[12], pdu[13], pdu[14], pdu[15]]);
            let reply = match ptype {
                11 => Some(build_bind_ack(call_id)),
                14 => None,
                0 if pdu.len() >= 24 => {
                    let opnum = u16::from_le_bytes([pdu[22], pdu[23]]);
                    tracing::debug!(opnum, "rpc request");
                    let body = match opnum {
                        15 => netshareenum_stub(shares),
                        _ => build_fault(call_id),
                    };
                    Some(response_pdu(call_id, &body))
                }
                _ => None,
            };
            if let Some(r) = reply {
                self.outbound.push_back(r);
            }
        }
    }
}

fn pdu_header(ptype: u8, call_id: u32, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(16 + body.len());
    p.extend_from_slice(&[5, 0]);
    p.push(ptype);
    p.push(0x03);
    p.extend_from_slice(&0x0000_0010u32.to_le_bytes());
    p.extend_from_slice(&((body.len() + 16) as u16).to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes());
    p.extend_from_slice(&call_id.to_le_bytes());
    p.extend_from_slice(body);
    p
}

fn response_pdu(call_id: u32, stub: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + stub.len());
    body.extend_from_slice(&(stub.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.push(0); body.push(0);
    body.extend_from_slice(stub);
    pdu_header(2, call_id, &body)
}

fn build_fault(call_id: u32) -> Vec<u8> {
    let mut body = vec![0u8; 4];
    body.extend_from_slice(&0u16.to_le_bytes());
    body.push(0); body.push(0);
    body.extend_from_slice(&0x1C01_0006u32.to_le_bytes());
    pdu_header(3, call_id, &body)
}

fn build_bind_ack(call_id: u32) -> Vec<u8> {
    let sec_addr = b"\\pipe\\srvsvc\0";
    let mut b = Vec::new();
    b.extend_from_slice(&0x10b8u16.to_le_bytes());
    b.extend_from_slice(&0x10b8u16.to_le_bytes());
    b.extend_from_slice(&0x12345678u32.to_le_bytes());
    b.extend_from_slice(&(sec_addr.len() as u16).to_le_bytes());
    b.extend_from_slice(sec_addr);
    while b.len() % 4 != 0 { b.push(0); }
    b.extend_from_slice(&1u16.to_le_bytes());
    b.push(0); b.push(0);
    b.extend_from_slice(&0u16.to_le_bytes()); // result
    b.extend_from_slice(&0u16.to_le_bytes()); // reason
    b.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    ]);
    b.extend_from_slice(&2u32.to_le_bytes());
    pdu_header(12, call_id, &b)
}

/// Build the NDR stub for a NetShareEnumAll level-1 response
/// ([MS-SRVS] §3.1.4.8, §2.2.4.33) marshalled per [MS-RPCE] NDR rules.
///
/// The `SHARE_INFO_1_CONTAINER` union arm is emitted in full — the array of
/// `SHARE_INFO_1` fixed parts (netname pointer, type, remark pointer) first,
/// then every pointee string deferred in pointer-appearance order — before the
/// trailing `TotalEntries`, `ResumeHandle` and return-code out-parameters.
/// Deferring the strings (rather than inlining each after its referent id) is
/// the NDR rule for pointers embedded in a conformant array; the `ms-ndr`
/// primitive layer handles referent ids, 4-byte alignment and the
/// `[size_is][length_is]` wchar payload.
pub fn netshareenum_stub(shares: &[ShareInfo]) -> Vec<u8> {
    let n = shares.len() as u32;
    let mut e = NdrEncoder::new();

    e.u32(1); // Level = 1
    e.u32(1); // SHARE_INFO union switch (container 1)
    e.referent(); // Ctr pointer
    e.u32(n); // Container.EntriesRead
    e.referent(); // Container.Buffer array pointer
    e.u32(n); // conformant array MaxCount

    // SHARE_INFO_1 fixed parts: netname ptr, type, remark ptr.
    for sh in shares {
        e.referent(); // netname pointer
        e.u32(sh.shi_type);
        e.referent(); // remark pointer
    }

    // Deferred string data, in the order the pointers appeared.
    for sh in shares {
        e.conformant_varying_wstr(&sh.netname);
        e.conformant_varying_wstr(&sh.remark);
    }

    e.u32(n); // TotalEntries
    e.referent(); // ResumeHandle pointer
    e.u32(0); // ResumeHandle value
    e.u32(0); // return WERROR = ERROR_SUCCESS
    e.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_ndr::NdrDecoder;

    fn reference_shares() -> Vec<ShareInfo> {
        vec![
            ShareInfo { netname: "public".into(), shi_type: 0, remark: String::new() },
            ShareInfo {
                netname: "IPC$".into(),
                shi_type: 0x8000_0003,
                remark: "IPC Service (ref)".into(),
            },
        ]
    }

    /// Decode our own stub back through the NDR reader and assert every field
    /// round-trips. This validates the [MS-SRVS] `SHARE_ENUM_STRUCT` layout
    /// (level, union switch, container, deferred strings, out-parameters)
    /// structurally rather than pinning it to one server's referent ids.
    fn decode_and_check(shares: &[ShareInfo]) {
        let stub = netshareenum_stub(shares);
        assert_eq!(stub.len() % 4, 0, "stub stays 4-byte aligned");

        let n = shares.len() as u32;
        let mut d = NdrDecoder::new(&stub);
        assert_eq!(d.u32().unwrap(), 1, "Level");
        assert_eq!(d.u32().unwrap(), 1, "union switch");
        assert_ne!(d.u32().unwrap(), 0, "container pointer non-null");
        assert_eq!(d.u32().unwrap(), n, "EntriesRead");
        assert_ne!(d.u32().unwrap(), 0, "buffer pointer non-null");
        assert_eq!(d.u32().unwrap(), n, "array MaxCount");

        let mut types = Vec::new();
        for _ in 0..n {
            assert_ne!(d.u32().unwrap(), 0, "netname pointer non-null");
            types.push(d.u32().unwrap());
            assert_ne!(d.u32().unwrap(), 0, "remark pointer non-null");
        }

        let mut decoded = Vec::new();
        for _ in 0..n {
            let netname = d.conformant_varying_wstr().unwrap();
            let remark = d.conformant_varying_wstr().unwrap();
            decoded.push((netname, remark));
        }

        assert_eq!(d.u32().unwrap(), n, "TotalEntries");
        assert_ne!(d.u32().unwrap(), 0, "resume-handle pointer non-null");
        assert_eq!(d.u32().unwrap(), 0, "resume-handle value");
        assert_eq!(d.u32().unwrap(), 0, "return WERROR = ERROR_SUCCESS");
        assert_eq!(d.remaining(), 0, "no trailing bytes");

        for (i, sh) in shares.iter().enumerate() {
            assert_eq!(types[i], sh.shi_type, "share {i} type");
            assert_eq!(decoded[i].0, sh.netname, "share {i} netname");
            assert_eq!(decoded[i].1, sh.remark, "share {i} remark");
        }
    }

    #[test]
    fn netshareenum_round_trips_reference_shares() {
        decode_and_check(&reference_shares());
    }

    #[test]
    fn netshareenum_scales_to_more_shares() {
        let shares = vec![
            ShareInfo { netname: "alpha".into(), shi_type: 0, remark: "one".into() },
            ShareInfo { netname: "beta".into(), shi_type: 0, remark: "two".into() },
            ShareInfo { netname: "IPC$".into(), shi_type: 0x8000_0003, remark: String::new() },
        ];
        decode_and_check(&shares);

        // Every embedded pointer must carry a distinct, non-zero referent id.
        let stub = netshareenum_stub(&shares);
        let mut refs = vec![
            u32::from_le_bytes([stub[8], stub[9], stub[10], stub[11]]),
            u32::from_le_bytes([stub[16], stub[17], stub[18], stub[19]]),
        ];
        for i in 0..shares.len() {
            let base = 24 + i * 12;
            refs.push(u32::from_le_bytes([stub[base], stub[base + 1], stub[base + 2], stub[base + 3]]));
            refs.push(u32::from_le_bytes([stub[base + 8], stub[base + 9], stub[base + 10], stub[base + 11]]));
        }
        let mut unique = refs.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), refs.len(), "referent ids must be unique");
    }
}
