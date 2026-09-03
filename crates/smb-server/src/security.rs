//! NT security-descriptor helpers built on the `win-sd` crate ([MS-DTYP]
//! §2.4.6). Marshalling of the self-relative `SECURITY_DESCRIPTOR` / `ACL` /
//! `SID` blobs is delegated to `win-sd` rather than hand-rolled here.
//!
//! The POSIX backend cannot express NT ACLs natively, so descriptors are
//! stored verbatim (see [`smb_server_vfs::Vfs::get_security`] /
//! [`smb_server_vfs::Vfs::set_security`]). When a file has no stored descriptor a
//! permissive default is synthesised so clients always see a valid
//! owner/group/DACL.

use win_sd::{AccessMask, SecurityDescriptor, SecurityDescriptorBuilder, Sid};

/// SECURITY_INFORMATION component-selector bits ([MS-DTYP] §2.4.7).
pub mod sec_info {
    /// Owner SID.
    pub const OWNER: u32 = 0x0000_0001;
    /// Group SID.
    pub const GROUP: u32 = 0x0000_0002;
    /// Discretionary ACL.
    pub const DACL: u32 = 0x0000_0004;
    /// System ACL.
    pub const SACL: u32 = 0x0000_0008;
    /// Default selection when the client passes 0 (owner + group + DACL).
    pub const DEFAULT: u32 = OWNER | GROUP | DACL;
}

/// Permissive default: owner/group `BUILTIN\Administrators`, DACL granting
/// `Everyone` full control. Returned when a file has no stored descriptor.
fn default_descriptor() -> SecurityDescriptor {
    SecurityDescriptorBuilder::new()
        .owner(Sid::administrators())
        .group(Sid::administrators())
        .allow(Sid::everyone(), AccessMask::FILE_ALL_ACCESS)
        .build()
}

/// Self-relative descriptor bytes for a QUERY SECURITY, keeping only the
/// components named in `additional`. `stored` is the backend's saved blob.
pub fn query_security(stored: Option<&[u8]>, additional: u32) -> Option<Vec<u8>> {
    let src = match stored {
        Some(bytes) => SecurityDescriptor::from_bytes(bytes).unwrap_or_else(|_| default_descriptor()),
        None => default_descriptor(),
    };
    let mut out = SecurityDescriptor::new();
    if additional & sec_info::OWNER != 0
        && let Some(o) = src.owner() {
            out.set_owner(o.clone());
        }
    if additional & sec_info::GROUP != 0
        && let Some(g) = src.group() {
            out.set_group(g.clone());
        }
    if additional & sec_info::DACL != 0
        && let Some(d) = src.dacl() {
            out.set_dacl(d.clone());
        }
    out.to_bytes().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_query_is_parseable_and_has_dacl() {
        let bytes = query_security(None, sec_info::DEFAULT).expect("encode");
        let sd = SecurityDescriptor::from_bytes(&bytes).expect("round-trip parse");
        assert!(sd.owner().is_some(), "owner present");
        assert!(sd.dacl().is_some(), "DACL present");
    }

    #[test]
    fn dacl_only_omits_owner() {
        let bytes = query_security(None, sec_info::DACL).expect("encode");
        let sd = SecurityDescriptor::from_bytes(&bytes).expect("parse");
        assert!(sd.owner().is_none(), "owner omitted when not requested");
        assert!(sd.dacl().is_some(), "DACL still present");
    }

    #[test]
    fn stored_descriptor_round_trips() {
        let stored = SecurityDescriptorBuilder::new()
            .owner(Sid::local_system())
            .allow(Sid::everyone(), AccessMask::FILE_GENERIC_READ)
            .build()
            .to_bytes()
            .unwrap();
        let out = query_security(Some(&stored), sec_info::OWNER).expect("encode");
        let sd = SecurityDescriptor::from_bytes(&out).expect("parse");
        assert_eq!(sd.owner(), Some(&Sid::local_system()), "stored owner preserved");
    }
}
