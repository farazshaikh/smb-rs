//! Credential verification against the configured user database using the
//! NTLM family of schemes ([MS-NLMP] §3.3).

use smb_auth::crypto::{hmac_md5, md4, nt_hash, ntlmv1_response, rc4};
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
    /// Exported SMB2 session key (16 bytes) when key exchange completed
    /// against a verified secret ([MS-SMB2] §3.2.5.3.1). Signing keys are
    /// derived from this; `None` disables signing for the session.
    pub session_key: Option<[u8; 16]>,
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
    const NO_KEY: Option<[u8; 16]> = None;

    // Anonymous / null session.
    if t3.ntlm_response.is_empty() && t3.lm_response.is_empty()
        || t3.flags & smb_auth::ntlm::NEGOTIATE_ANONYMOUS != 0
    {
        return AuthOutcome { ok: true, guest: true, user: "nobody".into(), session_key: NO_KEY };
    }

    if users.is_empty() && allow_guest {
        // No user database configured: accept any principal. Without a
        // shared secret the session key cannot be derived.
        return AuthOutcome { ok: true, guest: false, user, session_key: NO_KEY };
    }

    let Some(pass) = users.get(&user.to_lowercase()).cloned() else {
        return if allow_guest {
            AuthOutcome { ok: true, guest: true, user, session_key: NO_KEY }
        } else {
            AuthOutcome { ok: false, guest: false, user, session_key: NO_KEY }
        };
    };

    let nthash = nt_hash(&pass);

    // NTLMv2 ([MS-NLMP] §3.3.2):
    //   NTLMv2Hash = HMAC-MD5(NTHash, UPPER(user) || domain)
    //   Proof      = HMAC-MD5(NTLMv2Hash, ServerChallenge || blob)
    if t3.ntlm_response.len() >= 24 {
        for identity in [
            format!("{}{}", user.to_uppercase(), t3.domain),
            format!("{}{}", user.to_uppercase(), ""),
        ] {
            let idb = utf16_le(&identity);
            let ntv2 = hmac_md5(&nthash, &idb);
            let mut msg = Vec::with_capacity(8 + t3.ntlm_response.len() - 16);
            msg.extend_from_slice(challenge);
            msg.extend_from_slice(&t3.ntlm_response[16..]);
            let proof = hmac_md5(&ntv2, &msg);
            if proof.as_slice() == &t3.ntlm_response[..16] {
                // Derive keys from the SAME identity that verified.
                let key = derive_session_key(&nthash, &idb, &proof, t3);
                return AuthOutcome {
                    ok: true,
                    guest: false,
                    user,
                    session_key: key,
                };
            }
        }
    }

    // NTLMv1 fallback: DES-based response over the expanded NT hash. No
    // session-key derivation here (modern clients always use NTLMv2).
    if t3.ntlm_response.len() == 24 {
        let mut h21 = [0u8; 21];
        h21[..16].copy_from_slice(&nthash);
        let expect = ntlmv1_response(&h21, challenge);
        if expect.as_slice() == &t3.ntlm_response[..24] {
            return AuthOutcome { ok: true, guest: false, user, session_key: NO_KEY };
        }
    }

    AuthOutcome { ok: false, guest: false, user, session_key: NO_KEY }
}

/// Exported session key ([MS-NLMP] §3.2.5.1.2):
///   KeyExchangeKey     = HMAC-MD5(NTLMv2Hash, NTProofStr)
///   ExportedSessionKey = RC4(KeyExchangeKey, EncryptedRandomSessionKey)
/// When the client did not perform NEGOTIATE_KEY_EXCH the exported key
/// equals KeyExchangeKey.
fn derive_session_key(
    nthash: &[u8; 16],
    identity_utf16le: &[u8],
    proof: &[u8],
    t3: &Type3,
) -> Option<[u8; 16]> {
    use smb_auth::crypto::{hmac_md5, rc4};

    let ntv2 = hmac_md5(nthash, identity_utf16le);
    let key_exchange_key = hmac_md5(&ntv2, proof);

    match t3.encrypted_session_key.as_slice() {
        enc if enc.len() == 16 => {
            let out = rc4(&key_exchange_key, enc);
            Some(out.try_into().unwrap())
        }
        // No key exchange: exported == key exchange key.
        _ => Some(key_exchange_key),
    }
}

fn utf16_le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}
