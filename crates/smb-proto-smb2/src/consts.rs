//! SMB2/3 shared constants.

/// Signing enabled but not required.
pub const SIGNING_ENABLED: u16 = 0x0001;
/// Signing required.
pub const SIGNING_REQUIRED: u16 = 0x0002;
/// DFS support capability.
pub const CAP_DFS: u32 = 0x0000_0001;
/// Large MTU capability.
pub const CAP_LARGE_MTU: u32 = 0x0000_0004;
