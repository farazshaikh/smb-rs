//! Credential verification against the configured user database using the
//! NTLM family of schemes ([MS-NLMP] §3.3).

use smb_auth::crypto::{hmac_md5, md4, nt_hash, ntlmv1_response};
use smb_auth::ntlm::Type3;
use std::collections::HashMap;

/// Outcome of credential verification.
#[derive(Debug, Clone)]
pub struct AuthOutcome {
    /// Credentials accepted.
    pub ok: bool,
    /// Principal was mapped to guest rather than a real account.
    pub guest: bool,
    /// Effective username.
    pub user: String,
}

/// Verify NTLMv2 (preferred), NTLMv1-with-ESS or LM responses.
///
/// `server.users` empty + `allow_guest` accepts any principal; otherwise only
/// configured accounts (or explicit anonymous) succeed.
pub fn authenticate_ntlmssp(
    users: &HashMap<String, String>,
    allow_guest: bool,
    challenge: &[u8; 8],
    t3: &Type3,
) -> AuthOutcome {
    let user = t3.user.trim().to_string();

    // Anonymous / null session.
    if t3.ntlm_response.is_empty() && t3.lm_response.is_empty()
        || t3.flags & smb_auth::ntlm::NEGOTIATE_ANONYMOUS != 0
    {
        return AuthOutcome { ok: true, guest: true, user: "nobody".into() };
    }

    if users.is_empty() && allow_guest {
        return AuthOutcome { ok: true, guest: false, user };
    }

    let Some(pass) = users.get(&user.to_lowercase()).cloned() else {
        return if allow_guest {
            AuthOutcome { ok: true, guest: true, user }
        } else {
            AuthOutcome { ok: false, guest: false, user }
        };
    };

    let nthash = nt_hash(&pass);

    // NTLMv2 ([MS-NLMP] §3.3.2):
    //   NTLMv2Hash = HMAC-MD5(NTHash, UPPER(user) || domain)
    //   Proof      = HMAC-MD5(NTLMv2Hash, ServerChallenge || blob)
    if t3.ntlm_response.len() >= 24 {
        for identity in [format!("{}{}", user.to_uppercase(), t3.domain), format!("{}{}", user.to_uppercase(), "")] {
            let mut idb = Vec::with_capacity(identity.len() * 2);
            for u in identity.encode_utf16() {
                idb.extend_from_slice(&u.to_le_bytes());
            }
            let ntv2 = hmac_md5(&nthash, &idb);
            let mut msg = Vec::with_capacity(8 + t3.ntlm_response.len() - 16);
            msg.extend_from_slice(challenge);
            msg.extend_from_slice(&t3.ntlm_response[16..]);
            if hmac_md5(&ntv2, &msg)[..] == t3.ntlm_response[..16] {
                return AuthOutcome { ok: true, guest: false, user };
            }
        }
    }

    // NTLMv1 fallback: DES-based response over the expanded NT hash.
    if t3.ntlm_response.len() == 24 {
        let mut h21 = [0u8; 21];
        h21[..16].copy_from_slice(&md4_of(&pass));
        let expect = ntlmv1_response(&h21, challenge);
        if expect.as_slice() == &t3.ntlm_response[..24] {
            return AuthOutcome { ok: true, guest: false, user };
        }
    }

    AuthOutcome { ok: false, guest: false, user }
}

fn md4_of(pass: &str) -> [u8; 16] {
    use smb_auth::crypto::md4;
    md4(&{
        let mut b = Vec::with_capacity(pass.len() * 2);
        for u in pass.encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b
    })
}
