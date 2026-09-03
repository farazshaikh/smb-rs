//! `Decode` adapters over the existing `smb-server-proto-smb2` request parsers. Each is
//! a thin, zero-copy bridge: the frame is borrowed and the parser's `None`
//! (malformed) becomes `STATUS_INVALID_PARAMETER`.

use smb_server_proto::types::Status;
use smb_server_proto_smb2::commands::{
    ChangeNotifyReq, CloseReq, CreateReq, FlushReq, IoctlReq, LockReq, QueryDirReq, QueryInfoReq,
    ReadReq, SetInfoReq, WriteReq,
};
use smb_server_proto_smb2::session_setup::cmd;

use super::wire::Decode;

/// Generate a `Decode` impl that adapts an existing `Ty::parse(frame) -> Option<Ty>`.
macro_rules! decode_via_parse {
    ($ty:ty, $code:path) => {
        impl Decode for $ty {
            const COMMAND: u16 = $code;
            fn decode(frame: &[u8]) -> Result<Self, Status> {
                <$ty>::parse(frame).ok_or(Status::INVALID_PARAMETER)
            }
        }
    };
}

decode_via_parse!(CreateReq, cmd::CREATE);
decode_via_parse!(CloseReq, cmd::CLOSE);
decode_via_parse!(FlushReq, cmd::FLUSH);
decode_via_parse!(ReadReq, cmd::READ);
decode_via_parse!(WriteReq, cmd::WRITE);
decode_via_parse!(LockReq, cmd::LOCK);
decode_via_parse!(IoctlReq, cmd::IOCTL);
decode_via_parse!(QueryDirReq, cmd::QUERY_DIRECTORY);
decode_via_parse!(ChangeNotifyReq, cmd::CHANGE_NOTIFY);
decode_via_parse!(QueryInfoReq, cmd::QUERY_INFO);
decode_via_parse!(SetInfoReq, cmd::SET_INFO);
