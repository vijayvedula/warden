//! Signed per-action approval assertions.
//!
//! An approval is only trustworthy if (a) the approver is authenticated and
//! (b) the approval is bound to the *specific* action -- otherwise a free-text
//! `--by alice` can be forged, or one approval replayed against a different
//! call. An assertion is an ES256 JWT whose `kid` is the approver's identity
//! and whose `act_id` is the action's fingerprint (already a hash of
//! agent+tool+args). The proxy verifies the signature against an allowlist of
//! approver keys (a JWKS keyed by approver name) and that `act_id` matches the
//! action being released -- else it fails closed.

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Assertion {
    /// The approver identity (must equal the signing key's `kid`).
    sub: String,
    /// The action fingerprint this approval is bound to.
    act_id: String,
    ts: u64,
}

/// Sign an approval assertion (ES256, header `kid` = approver).
pub fn sign(key_pem: &[u8], approver: &str, act_id: &str, ts: u64) -> Result<String, String> {
    let key = EncodingKey::from_ec_pem(key_pem).map_err(|e| format!("bad approver key: {e}"))?;
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(approver.to_string());
    let claims = Assertion {
        sub: approver.to_string(),
        act_id: act_id.to_string(),
        ts,
    };
    encode(&header, &claims, &key).map_err(|e| format!("sign approval: {e}"))
}

/// Verify an approval assertion against the allowlisted approver keys, bound to
/// `expected_act_id`. Returns the verified approver identity.
pub fn verify(jwt: &str, approver_keys: &JwkSet, expected_act_id: &str) -> Result<String, String> {
    let header = decode_header(jwt).map_err(|e| format!("bad assertion header: {e}"))?;
    if header.alg != Algorithm::ES256 {
        return Err(format!("rejected assertion alg {:?}", header.alg));
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or("approval assertion has no `kid` (approver)")?;
    let jwk = approver_keys
        .find(kid)
        .ok_or_else(|| format!("approver `{kid}` is not in the allowlist"))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| format!("bad approver key: {e}"))?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;

    let data = decode::<Assertion>(jwt, &key, &validation)
        .map_err(|e| format!("approval signature invalid: {e}"))?;
    let a = data.claims;
    if a.sub != kid {
        return Err("approver/sub mismatch in assertion".to_string());
    }
    if a.act_id != expected_act_id {
        return Err("approval is for a different action (act_id mismatch)".to_string());
    }
    Ok(a.sub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PRIV: &str = include_str!("../fixtures/test_ec_priv.pem");

    fn jwks() -> JwkSet {
        // JWKS derived from the fixture public key, kid = "alice".
        serde_json::from_value(json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "alice",
                "x": "tLLpBYFaVoNTSnBrHYnRD6_qtqpFZqP7XcekRO62BgU",
                "y": "DAzZl1_TMsBtEP3IjaYDelO2xc3Zo_cY2rkgWhTw2Qk"
            }]
        }))
        .unwrap()
    }

    #[test]
    fn sign_then_verify_bound_to_action() {
        let jwt = sign(PRIV.as_bytes(), "alice", "act-123", 100).unwrap();
        assert_eq!(verify(&jwt, &jwks(), "act-123").unwrap(), "alice");
        // Replay against a different action is rejected.
        assert!(verify(&jwt, &jwks(), "act-999").is_err());
    }

    #[test]
    fn unknown_approver_rejected() {
        let jwt = sign(PRIV.as_bytes(), "mallory", "act-123", 100).unwrap();
        // kid "mallory" not in the allowlist.
        assert!(verify(&jwt, &jwks(), "act-123").is_err());
    }
}
