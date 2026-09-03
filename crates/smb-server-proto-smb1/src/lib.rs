//! SMB1 wire structures ([MS-SMB] extensions over [MS-CIFS]).
//!
//! Every module corresponds to a section of the specification:
//!
//! | Module | Spec coverage |
//! |---|---|
//! | [`consts`]  | command opcodes ([MS-CIFS] §2.2.2, extended by [MS-SMB]) |
//! | [`header`]  | SMB header ([MS-SMB] §2.2.3.1) and response/AndX assembly |
//! | [`negotiate`] | [MS-SMB] §2.2.4.5 — `SMB_COM_NEGOTIATE` (0x72) |
//! | [`session_setup`] | [MS-SMB] §2.2.4.6 — `SMB_COM_SESSION_SETUP_ANDX` (0x73) |
//! | [`tree_connect`] | [MS-SMB] §2.2.4.7 — `SMB_COM_TREE_CONNECT_ANDX` (0x75) / disconnect |
//! | [`create`] | [MS-SMB] §2.2.4.9 — `SMB_COM_NT_CREATE_ANDX` (0xA2) |
//! | [`rw`] | `READ_ANDX` / `WRITE_ANDX` ([MS-CIFS] §2.2.4.x, extended by [MS-SMB]) |
//! | [`trans2`] | [MS-SMB] §2.2.6 — TRANSACTION2 subcommand envelope + FIND_* (§2.2.6.1/2), QUERY_FS (§2.2.6.3), QUERY/SET PATH/FILE (§2.2.6.5–8); information levels per §2.2.8 |
//! | [`legacy`] | Core/LANMAN-era commands: MKDIR/RMDIR/CHECKDIR, DELETE, RENAME, QUERY/SET_INFORMATION ([MS-CIFS]) |
//! | [`misc`] | ECHO, LOGOFF_ANDX, QUERY_INFORMATION_DISK, PROCESS_EXIT |

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

pub mod consts;
pub mod create;
pub mod find;
pub mod header;
pub mod legacy;
pub mod misc;
pub mod negotiate;
pub mod query;
pub mod rw;
pub mod session_setup;
pub mod trans2;
pub mod tree_connect;

pub use header::{parse_header, Header, RespBody};
pub use trans2::find_level;
