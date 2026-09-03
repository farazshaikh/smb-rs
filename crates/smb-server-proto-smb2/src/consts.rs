//! SMB2/3 shared constants.

/// Signing enabled but not required.
pub const SIGNING_ENABLED: u16 = 0x0001;
/// Signing required.
pub const SIGNING_REQUIRED: u16 = 0x0002;
/// DFS support capability.
pub const CAP_DFS: u32 = 0x0000_0001;
/// Large MTU capability.
pub const CAP_LARGE_MTU: u32 = 0x0000_0004;

/// Byte offsets and sizes of the 64-byte SMB2 packet header ([MS-SMB2] §2.2.1.2).
pub mod hdr {
    /// Total SMB2 packet header length.
    pub const LEN: usize = 64;
    /// ProtocolId (`\xFESMB`) offset.
    pub const PROTOCOL_ID: usize = 0;
    /// StructureSize offset (the value is always 64).
    pub const STRUCTURE_SIZE: usize = 4;
    /// CreditCharge offset.
    pub const CREDIT_CHARGE: usize = 6;
    /// Status / ChannelSequence offset.
    pub const STATUS: usize = 8;
    /// Command offset.
    pub const COMMAND: usize = 12;
    /// CreditRequest / CreditResponse offset.
    pub const CREDIT: usize = 14;
    /// Flags offset.
    pub const FLAGS: usize = 16;
    /// NextCommand offset (compound chaining).
    pub const NEXT_COMMAND: usize = 20;
    /// MessageId offset.
    pub const MESSAGE_ID: usize = 24;
    /// AsyncId offset in async mode (overlaps Reserved + TreeId).
    pub const ASYNC_ID: usize = 32;
    /// TreeId offset in sync mode.
    pub const TREE_ID: usize = 36;
    /// SessionId offset.
    pub const SESSION_ID: usize = 40;
    /// Signature offset.
    pub const SIGNATURE: usize = 48;
    /// Signature length.
    pub const SIGNATURE_LEN: usize = 16;
    /// Compound requests/responses are 8-byte aligned ([MS-SMB2] §3.3.4.1).
    pub const ALIGN: usize = 8;
}

/// SMB2 header `Flags` bits ([MS-SMB2] §2.2.1.2).
pub mod hdr_flags {
    /// SMB2_FLAGS_SERVER_TO_REDIR — response, not request.
    pub const SERVER_TO_REDIR: u32 = 0x0000_0001;
    /// SMB2_FLAGS_ASYNC_COMMAND — the header carries an AsyncId.
    pub const ASYNC_COMMAND: u32 = 0x0000_0002;
    /// SMB2_FLAGS_RELATED_OPERATIONS — compound request shares the prior FileId.
    pub const RELATED_OPERATIONS: u32 = 0x0000_0004;
    /// SMB2_FLAGS_SIGNED — the PDU carries a signature.
    pub const SIGNED: u32 = 0x0000_0008;
    /// SMB2_FLAGS_REPLAY_OPERATION — the request is a replay ([MS-SMB2] §2.2.1.2).
    pub const REPLAY_OPERATION: u32 = 0x2000_0000;
}

/// AEAD parameters for SMB3 transform (encrypted) messages ([MS-SMB2] §3.1.4.3).
pub mod aead {
    /// AES-128-GCM nonce length.
    pub const GCM_NONCE_LEN: usize = 12;
    /// AES-128-CCM nonce length.
    pub const CCM_NONCE_LEN: usize = 11;
    /// AEAD authentication tag length (lands in the transform Signature field).
    pub const TAG_LEN: usize = 16;
}
