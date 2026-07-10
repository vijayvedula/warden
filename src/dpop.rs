//! DPoP -- sender-constrained tokens (RFC 9449).
//!
//! A bearer token can be replayed if stolen. DPoP binds the token to a key the
//! client holds: the access token carries `cnf.jkt` (a JWK thumbprint), and
//! every request carries a `DPoP` proof -- a short JWT signed by that key,
//! covering the HTTP method (`htm`) and URL (`htu`). Warden verifies the proof's
//! signature, that it covers *this* request, and that its key's thumbprint
//! matches the token's `cnf.jkt`. A stolen token without the private key is
//! useless. (DPoP applies on the HTTP transport, which carries method + URL.)

use crate::util::sha256_bytes;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Process-wide cache of DPoP proof `jti`s seen within the freshness window,
/// so a captured proof can't be replayed while it's still valid.
static DPOP_SEEN: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();

fn dpop_seen() -> &'static Mutex<HashMap<String, u64>> {
    DPOP_SEEN.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record a proof `jti`; reject (replay) if already seen inside `window`.
fn mark_jti(jti: &str, now: u64, window: u64) -> Result<(), String> {
    let mut seen = dpop_seen().lock().unwrap();
    seen.retain(|_, t| now.saturating_sub(*t) <= window);
    if seen.contains_key(jti) {
        return Err("DPoP proof replay (jti already used)".to_string());
    }
    seen.insert(jti.to_string(), now);
    Ok(())
}

#[derive(Debug, Deserialize)]
struct Proof {
    htm: String,
    htu: String,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    jti: Option<String>,
}

fn is_asymmetric(a: Algorithm) -> bool {
    !matches!(a, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}

/// RFC 7638 JWK thumbprint (SHA-256, base64url). Required members only, in
/// lexicographic order, compact JSON.
pub fn thumbprint(jwk: &Jwk) -> Result<String, String> {
    let v = serde_json::to_value(jwk).map_err(|e| format!("jwk: {e}"))?;
    let q = |k: &str| serde_json::to_string(&v[k]).unwrap_or_default(); // JSON-quoted member
    let kty = v["kty"].as_str().ok_or("jwk missing kty")?;
    let canon = match kty {
        "EC" => format!(
            "{{\"crv\":{},\"kty\":\"EC\",\"x\":{},\"y\":{}}}",
            q("crv"),
            q("x"),
            q("y")
        ),
        "RSA" => format!("{{\"e\":{},\"kty\":\"RSA\",\"n\":{}}}", q("e"), q("n")),
        "OKP" => format!("{{\"crv\":{},\"kty\":\"OKP\",\"x\":{}}}", q("crv"), q("x")),
        other => return Err(format!("unsupported jwk kty: {other}")),
    };
    Ok(URL_SAFE_NO_PAD.encode(sha256_bytes(canon.as_bytes())))
}

/// Verify a DPoP proof for a request, bound to the token's `expected_jkt`.
pub fn verify_proof(
    proof: &str,
    method: &str,
    url: &str,
    expected_jkt: &str,
    now: u64,
    leeway: u64,
) -> Result<(), String> {
    let header = decode_header(proof).map_err(|e| format!("bad DPoP header: {e}"))?;
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err("DPoP proof typ is not dpop+jwt".to_string());
    }
    if !is_asymmetric(header.alg) {
        return Err("DPoP proof must use an asymmetric algorithm".to_string());
    }
    let jwk = header.jwk.ok_or("DPoP proof missing embedded jwk")?;
    let key = DecodingKey::from_jwk(&jwk).map_err(|e| format!("bad DPoP key: {e}"))?;

    let mut v = Validation::new(header.alg);
    v.algorithms = vec![header.alg];
    v.required_spec_claims.clear();
    v.validate_exp = false;
    v.validate_aud = false;
    let data =
        decode::<Proof>(proof, &key, &v).map_err(|e| format!("DPoP signature invalid: {e}"))?;
    let p = data.claims;

    if !p.htm.eq_ignore_ascii_case(method) {
        return Err(format!("DPoP htm `{}` != request method `{method}`", p.htm));
    }
    if normalize_url(&p.htu) != normalize_url(url) {
        return Err("DPoP htu does not match the request URL".to_string());
    }
    if let Some(iat) = p.iat {
        if iat > now + leeway {
            return Err("DPoP proof iat in the future".to_string());
        }
        if now > iat && now - iat > 300 + leeway {
            return Err("DPoP proof is stale (> 5 min)".to_string());
        }
    }
    let jkt = thumbprint(&jwk)?;
    if jkt != expected_jkt {
        return Err("DPoP key thumbprint does not match token cnf.jkt".to_string());
    }
    // Anti-replay: a fully-valid proof's jti may be used only once per window.
    let jti = p.jti.as_deref().ok_or("DPoP proof missing jti")?;
    mark_jti(jti, now, 300 + leeway)?;
    Ok(())
}

/// Compare URLs ignoring query/fragment (RFC 9449 htu).
fn normalize_url(u: &str) -> String {
    let base = u.split(['?', '#']).next().unwrap_or(u);
    base.trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    const PRIV: &str = include_str!("../fixtures/test_ec_priv.pem");
    const JWKS: &str = include_str!("../fixtures/test_jwks.json");

    fn pub_jwk() -> Jwk {
        let set: jsonwebtoken::jwk::JwkSet = serde_json::from_str(JWKS).unwrap();
        set.keys[0].clone()
    }

    fn make_proof(htm: &str, htu: &str, iat: u64, jti: &str) -> String {
        let mut h = Header::new(Algorithm::ES256);
        h.typ = Some("dpop+jwt".to_string());
        h.jwk = Some(pub_jwk());
        let key = EncodingKey::from_ec_pem(PRIV.as_bytes()).unwrap();
        encode(
            &h,
            &json!({ "htm": htm, "htu": htu, "iat": iat, "jti": jti }),
            &key,
        )
        .unwrap()
    }

    #[test]
    fn valid_proof_bound_to_token() {
        let jkt = thumbprint(&pub_jwk()).unwrap();
        let proof = make_proof("POST", "https://warden/mcp", 1000, "valid1");
        assert!(verify_proof(&proof, "POST", "https://warden/mcp?x=1", &jkt, 1000, 30).is_ok());
    }

    #[test]
    fn replayed_proof_is_rejected() {
        let jkt = thumbprint(&pub_jwk()).unwrap();
        let proof = make_proof("POST", "https://warden/mcp", 1000, "replay1");
        // First use succeeds; the same proof (same jti) again is a replay.
        assert!(verify_proof(&proof, "POST", "https://warden/mcp", &jkt, 1000, 30).is_ok());
        assert!(verify_proof(&proof, "POST", "https://warden/mcp", &jkt, 1001, 30).is_err());
    }

    #[test]
    fn rejects_method_url_jkt_and_replay() {
        let jkt = thumbprint(&pub_jwk()).unwrap();
        let proof = make_proof("POST", "https://warden/mcp", 1000, "rej1");
        // wrong method
        assert!(verify_proof(&proof, "GET", "https://warden/mcp", &jkt, 1000, 30).is_err());
        // wrong url
        assert!(verify_proof(&proof, "POST", "https://warden/other", &jkt, 1000, 30).is_err());
        // wrong token binding (attacker presents a valid proof but for a token bound to a different key)
        assert!(verify_proof(
            &proof,
            "POST",
            "https://warden/mcp",
            "someoneelsejkt",
            1000,
            30
        )
        .is_err());
        // stale
        assert!(verify_proof(&proof, "POST", "https://warden/mcp", &jkt, 9999, 30).is_err());
    }
}
