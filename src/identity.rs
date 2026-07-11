//! Identity: the signed session token that carries *who an agent acts for*.
//!
//! Warden stays stateless on identity -- it verifies a token and trusts its
//! claims. All relationship/role resolution (OpenFGA, Zanzibar, JIT graph
//! walks) is offloaded to whoever mints the token. See
//! `docs/accountable-authorization.md`.
//!
//! The token uses RFC 8693 (OAuth token exchange) delegation semantics: `sub`
//! is the accountable party (a human), `act` is the acting party and nests to
//! express the full chain `human -> [service] -> agent`.
//!
//! Two verification modes:
//!   - **JWT (production)** -- a standard compact JWT verified against an
//!     asymmetric key from a JWKS (matched by `kid`) or a PEM public key.
//!     Algorithm is restricted to asymmetric families, which blocks the classic
//!     RS256->HS256 confusion downgrade. Selected by configuring `--jwks` or
//!     `--issuer-key`.
//!   - **Dev envelope** -- a `{ "claims": {...}, "sig": "<hex>" }` file with an
//!     optional keyed-digest signature, for local/demo use only. Selected when
//!     no JWT verification key is configured.

use crate::util::{canonical_json, sha256_hex};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;

/// One link in the delegation chain (RFC 8693 `act`).
#[derive(Debug, Clone, Deserialize)]
pub struct Act {
    pub sub: String,
    #[serde(default)]
    pub act: Option<Box<Act>>,
}

/// A relationship tuple scoping the token to a specific resource (ReBAC).
#[derive(Debug, Clone, Deserialize)]
pub struct Rel {
    pub relation: String,
    pub resource: String,
}

/// The token claims. Mirrors the schema in the design doc.
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    #[serde(default)]
    #[allow(dead_code)]
    pub iss: String,
    #[serde(default)]
    pub aud: String,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub nbf: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    pub iat: Option<u64>,
    #[serde(default)]
    pub jti: String,
    /// The accountable party (a human). Empty => no accountability => reject.
    #[serde(default)]
    pub sub: String,
    /// The acting chain. The leaf `sub` must match the connecting agent.
    #[serde(default)]
    pub act: Option<Act>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub attrs: Map<String, Value>,
    #[serde(default)]
    pub rel: Vec<Rel>,
    #[serde(default)]
    pub scope: Vec<String>,
    /// Trusted resource attributes: resource id -> {attr: value}. Powers
    /// `resource:` policy conditions.
    #[serde(default)]
    pub resource_attrs: Map<String, Value>,
    /// Confirmation claim (RFC 7800) -- binds the token to a proof key. `jkt` is
    /// the JWK SHA-256 thumbprint for DPoP sender-constraint (RFC 9449).
    #[serde(default)]
    pub cnf: Option<Cnf>,
}

/// RFC 7800 confirmation claim.
#[derive(Debug, Clone, Deserialize)]
pub struct Cnf {
    /// DPoP JWK thumbprint (RFC 9449).
    #[serde(default)]
    pub jkt: Option<String>,
}

/// On-disk dev envelope: claims plus an optional detached signature.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenFile {
    pub claims: Claims,
    #[serde(default)]
    pub sig: Option<String>,
}

/// A token that has passed verification.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    pub claims: Claims,
    /// Whether the token was cryptographically verified (JWT, or dev keyed sig).
    pub signed: bool,
}

/// Verification configuration, assembled from CLI flags.
#[derive(Debug, Default, Clone)]
pub struct VerifyOpts {
    pub agent: String,
    pub now: u64,
    pub expected_aud: Option<String>,
    pub expected_iss: Option<String>,
    pub leeway: u64,
    /// JWT mode: path to a JWKS file (keys matched by `kid`).
    pub jwks_path: Option<String>,
    /// JWT mode: a JWKS URL fetched over HTTPS (cached, refetched on key rotation).
    pub jwks_url: Option<String>,
    /// JWT mode: path to a single PEM public key.
    pub pem_path: Option<String>,
    /// Dev-envelope mode: keyed-digest secret (None => unsigned dev token).
    pub dev_key: Option<String>,
    /// RFC 9068: require the JWT `typ` header to be `at+jwt`.
    pub require_at_jwt: bool,
}

impl VerifyOpts {
    fn jwt_mode(&self) -> bool {
        self.jwks_path.is_some() || self.pem_path.is_some() || self.jwks_url.is_some()
    }
}

/// Process-wide JWKS cache: url -> (raw text, fetched-at). 5-minute TTL.
static JWKS_CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, (String, u64)>>> =
    std::sync::OnceLock::new();

fn jwks_cache() -> &'static std::sync::Mutex<HashMap<String, (String, u64)>> {
    JWKS_CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Fetch a JWKS over HTTPS with a 5-minute cache; `force` bypasses the cache
/// (used on key rotation when a `kid` is not found).
fn fetch_jwks(url: &str, now: u64, force: bool) -> Result<JwkSet, String> {
    if !force {
        if let Some((text, ts)) = jwks_cache().lock().unwrap().get(url) {
            if now.saturating_sub(*ts) < 300 {
                return serde_json::from_str(text).map_err(|e| format!("cached jwks: {e}"));
            }
        }
    }
    let text = crate::net::get_text(url)?;
    let set: JwkSet = serde_json::from_str(&text).map_err(|e| format!("fetched jwks: {e}"))?;
    jwks_cache()
        .lock()
        .unwrap()
        .insert(url.to_string(), (text, now));
    Ok(set)
}

/// OIDC discovery: resolve the `jwks_uri` from an issuer's metadata document.
pub fn discover_jwks_uri(issuer_url: &str) -> Result<String, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );
    let text = crate::net::get_text(&url)?;
    let doc: Value = serde_json::from_str(&text).map_err(|e| format!("discovery doc: {e}"))?;
    doc.get("jwks_uri")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "discovery: no jwks_uri".to_string())
}

/// Asymmetric algorithms we accept in JWT mode. HMAC is deliberately excluded
/// so an attacker can't present an HS256 token signed with the public key.
const ASYMMETRIC_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

impl Claims {
    /// The acting chain from outermost service down to the leaf agent.
    pub fn act_chain(&self) -> Vec<String> {
        let mut chain = Vec::new();
        let mut cur = self.act.as_ref();
        while let Some(a) = cur {
            chain.push(a.sub.clone());
            cur = a.act.as_deref();
        }
        chain
    }

    /// The leaf actor -- the identity expected on the wire.
    pub fn leaf_actor(&self) -> Option<String> {
        self.act_chain().pop()
    }

    /// Relationship tuples as `(relation, resource)` pairs.
    pub fn rel_pairs(&self) -> Vec<(String, String)> {
        self.rel
            .iter()
            .map(|r| (r.relation.clone(), r.resource.clone()))
            .collect()
    }

    /// The DPoP JWK thumbprint this token is bound to, if sender-constrained.
    pub fn cnf_jkt(&self) -> Option<&str> {
        self.cnf.as_ref().and_then(|c| c.jkt.as_deref())
    }
}

/// Load and verify a session token from a file, dispatching on mode.
pub fn load_and_verify(path: &str, opts: &VerifyOpts) -> Result<VerifiedToken, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read token: {e}"))?;
    verify_token_str(text.trim(), opts)
}

/// Verify an in-memory token string (the per-request path for the HTTP gateway,
/// where each `tools/call` may carry a different user's delegation token as a
/// bearer). Same verification as `load_and_verify`, minus the file read.
pub fn verify_token_str(text: &str, opts: &VerifyOpts) -> Result<VerifiedToken, String> {
    let text = text.trim();
    if opts.jwt_mode() {
        let header = decode_header(text).map_err(|e| format!("invalid JWT header: {e}"))?;
        let key = resolve_key(&header, opts)?;
        verify_jwt(text, &key, opts)
    } else {
        // Dev envelope path.
        let envelope: Value =
            serde_json::from_str(text).map_err(|e| format!("invalid token json: {e}"))?;
        let raw_claims = envelope
            .get("claims")
            .ok_or("token missing `claims` object")?
            .clone();
        let file: TokenFile =
            serde_json::from_value(envelope).map_err(|e| format!("invalid token shape: {e}"))?;
        verify_envelope(file.claims, file.sig, &raw_claims, opts)
    }
}

/// Resolve the verification key for a JWT from JWKS (by `kid`) or PEM.
fn resolve_key(header: &jsonwebtoken::Header, opts: &VerifyOpts) -> Result<DecodingKey, String> {
    if let Some(url) = &opts.jwks_url {
        let kid = header
            .kid
            .as_deref()
            .ok_or("JWT has no `kid`; cannot select a JWKS key")?;
        // Try cached keys; on a miss, refetch once (handles key rotation).
        for force in [false, true] {
            let set = fetch_jwks(url, opts.now, force)?;
            if let Some(jwk) = set.find(kid) {
                return DecodingKey::from_jwk(jwk).map_err(|e| format!("bad JWKS key: {e}"));
            }
        }
        Err(format!("no JWKS key with kid `{kid}` (after refresh)"))
    } else if let Some(jwks_path) = &opts.jwks_path {
        let text = std::fs::read_to_string(jwks_path).map_err(|e| format!("read jwks: {e}"))?;
        let set: JwkSet = serde_json::from_str(&text).map_err(|e| format!("invalid jwks: {e}"))?;
        let kid = header
            .kid
            .as_deref()
            .ok_or("JWT has no `kid`; cannot select a JWKS key")?;
        let jwk = set
            .find(kid)
            .ok_or_else(|| format!("no JWKS key with kid `{kid}`"))?;
        DecodingKey::from_jwk(jwk).map_err(|e| format!("bad JWKS key: {e}"))
    } else if let Some(pem_path) = &opts.pem_path {
        let pem = std::fs::read(pem_path).map_err(|e| format!("read issuer key: {e}"))?;
        match header.alg {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {
                DecodingKey::from_rsa_pem(&pem).map_err(|e| format!("bad RSA key: {e}"))
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                DecodingKey::from_ec_pem(&pem).map_err(|e| format!("bad EC key: {e}"))
            }
            Algorithm::EdDSA => {
                DecodingKey::from_ed_pem(&pem).map_err(|e| format!("bad Ed key: {e}"))
            }
            other => Err(format!("unsupported JWT algorithm: {other:?}")),
        }
    } else {
        Err("no JWT verification key configured".to_string())
    }
}

/// Verify a compact JWT against `key`, then enforce Warden's actor/sub rules.
fn verify_jwt(token: &str, key: &DecodingKey, opts: &VerifyOpts) -> Result<VerifiedToken, String> {
    let header = decode_header(token).map_err(|e| format!("invalid JWT header: {e}"))?;
    // Asymmetric-only: block the RS256->HS256 confusion downgrade before decode.
    if !ASYMMETRIC_ALGS.contains(&header.alg) {
        return Err(format!(
            "rejected JWT algorithm {:?} (asymmetric only)",
            header.alg
        ));
    }
    // RFC 9068: OAuth access tokens carry `typ: at+jwt` (or `application/at+jwt`).
    if opts.require_at_jwt {
        let typ = header.typ.as_deref().unwrap_or("").to_ascii_lowercase();
        if typ != "at+jwt" && typ != "application/at+jwt" {
            return Err("RFC 9068: JWT `typ` is not at+jwt".to_string());
        }
    }
    let mut validation = Validation::new(header.alg);
    validation.algorithms = vec![header.alg];
    validation.leeway = opts.leeway;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    match &opts.expected_aud {
        Some(aud) => {
            validation.set_audience(&[aud]);
            // `jsonwebtoken` only checks `aud` when the claim is PRESENT; a token
            // that omits `aud` would otherwise pass despite `--aud`. Require it so
            // an audience-less token (e.g. one minted for a different relying
            // party) fails closed.
            validation.required_spec_claims.insert("aud".to_string());
        }
        None => validation.validate_aud = false,
    }
    if let Some(iss) = &opts.expected_iss {
        // Comma-separated issuer allowlist (multi-tenant / federation).
        let allow: Vec<&str> = iss
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        validation.set_issuer(&allow);
        // Same absent-claim gap: require `iss` so a token without one can't skip
        // the issuer allowlist.
        validation.required_spec_claims.insert("iss".to_string());
    }

    let data = decode::<Claims>(token, key, &validation)
        .map_err(|e| format!("JWT verification failed: {e}"))?;
    let claims = enforce_warden_rules(data.claims, &opts.agent)?;
    Ok(VerifiedToken {
        claims,
        signed: true,
    })
}

/// Verify a dev-envelope token (keyed digest), then Warden's actor/sub rules.
fn verify_envelope(
    claims: Claims,
    sig: Option<String>,
    raw_claims: &Value,
    opts: &VerifyOpts,
) -> Result<VerifiedToken, String> {
    let signed = match &opts.dev_key {
        Some(k) => {
            let provided = sig.ok_or("token has no signature but a key is configured")?;
            if provided != sign(raw_claims, k) {
                return Err("token signature mismatch".to_string());
            }
            true
        }
        None => false,
    };
    if let Some(aud) = &opts.expected_aud {
        if &claims.aud != aud {
            return Err(format!(
                "audience mismatch: token aud `{}` != expected `{aud}`",
                claims.aud
            ));
        }
    }
    if let Some(nbf) = claims.nbf {
        if opts.now + opts.leeway < nbf {
            return Err("token not yet valid (nbf in the future)".to_string());
        }
    }
    if let Some(exp) = claims.exp {
        if opts.now >= exp + opts.leeway {
            return Err("token expired".to_string());
        }
    }
    let claims = enforce_warden_rules(claims, &opts.agent)?;
    Ok(VerifiedToken { claims, signed })
}

/// The accountability invariants Warden enforces on top of signature/time:
/// a named accountable subject, and a leaf actor matching the wire identity.
fn enforce_warden_rules(claims: Claims, agent: &str) -> Result<Claims, String> {
    if claims.sub.trim().is_empty() {
        return Err("no accountable subject (`sub`) -- failing closed".to_string());
    }
    match claims.leaf_actor() {
        None => Err("token has no acting chain (`act`)".to_string()),
        Some(leaf) if leaf != agent => Err(format!(
            "wire identity `{agent}` does not match token actor `{leaf}`"
        )),
        Some(_) => Ok(claims),
    }
}

/// Dev-envelope keyed digest over the canonical claims.
pub fn sign(raw_claims: &Value, key: &str) -> String {
    sha256_hex(&format!("{key}|{}", canonical_json(raw_claims)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    // Throwaway ES256 keypair (test fixture only -- never used in production).
    const EC_PRIV: &str = include_str!("../fixtures/test_ec_priv.pem");
    const EC_PUB: &str = include_str!("../fixtures/test_ec_pub.pem");

    fn opts(aud: Option<&str>, agent: &str) -> VerifyOpts {
        VerifyOpts {
            agent: agent.to_string(),
            now: 1000,
            expected_aud: aud.map(|s| s.to_string()),
            expected_iss: None,
            leeway: 0,
            jwks_path: None,
            jwks_url: None,
            pem_path: Some("inline".to_string()), // marks JWT mode
            dev_key: None,
            require_at_jwt: false,
        }
    }

    #[test]
    fn rejects_non_at_jwt_when_required() {
        let v = claims_json();
        let jwt = sign_es256(&v, "k1");
        let mut o = opts(Some("warden:test"), "agent:bot-7");
        o.require_at_jwt = true; // RFC 9068 enforcement on a plain JWT (no typ)
        assert!(verify_jwt(&jwt, &ec_pub(), &o).is_err());
        o.require_at_jwt = false;
        assert!(verify_jwt(&jwt, &ec_pub(), &o).is_ok());
    }

    #[test]
    fn jwt_without_aud_is_rejected_when_aud_expected() {
        // A validly-signed token that OMITS `aud` must not pass when `--aud` is
        // set (jsonwebtoken only checks aud when present; we now require it).
        let mut claims = claims_json();
        claims.as_object_mut().unwrap().remove("aud");
        let jwt = sign_es256(&claims, "k1");
        assert!(verify_jwt(&jwt, &ec_pub(), &opts(Some("warden:test"), "agent:bot-7")).is_err());
        // With no expected aud configured, an aud-less token is still fine.
        assert!(verify_jwt(&jwt, &ec_pub(), &opts(None, "agent:bot-7")).is_ok());
    }

    fn claims_json() -> Value {
        json!({
            "iss": "idp", "aud": "warden:test", "exp": 4102444800u64, "jti": "tok_1",
            "sub": "human:alice",
            "act": { "sub": "service:recon", "act": { "sub": "agent:bot-7" } },
            "roles": ["ops.reconciler"],
            "rel": [{ "relation": "manages", "resource": "account:123" }],
            "scope": ["wire_funds"]
        })
    }

    fn sign_es256(claims: &Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_ec_pem(EC_PRIV.as_bytes()).unwrap();
        encode(&header, claims, &key).unwrap()
    }

    fn ec_pub() -> DecodingKey {
        DecodingKey::from_ec_pem(EC_PUB.as_bytes()).unwrap()
    }

    #[test]
    fn es256_verifies_and_extracts_chain() {
        let jwt = sign_es256(&claims_json(), "k1");
        let t = verify_jwt(&jwt, &ec_pub(), &opts(Some("warden:test"), "agent:bot-7")).unwrap();
        assert!(t.signed);
        assert_eq!(t.claims.sub, "human:alice");
        assert_eq!(t.claims.act_chain(), vec!["service:recon", "agent:bot-7"]);
    }

    #[test]
    fn es256_rejects_wrong_actor_and_aud() {
        let jwt = sign_es256(&claims_json(), "k1");
        assert!(verify_jwt(&jwt, &ec_pub(), &opts(Some("warden:test"), "agent:evil")).is_err());
        assert!(verify_jwt(&jwt, &ec_pub(), &opts(Some("warden:other"), "agent:bot-7")).is_err());
    }

    #[test]
    fn es256_rejects_expired() {
        let mut c = claims_json();
        c["exp"] = json!(1u64); // long past
        let jwt = sign_es256(&c, "k1");
        assert!(verify_jwt(&jwt, &ec_pub(), &opts(Some("warden:test"), "agent:bot-7")).is_err());
    }

    #[test]
    fn es256_rejects_missing_sub() {
        let mut c = claims_json();
        c["sub"] = json!("");
        let jwt = sign_es256(&c, "k1");
        assert!(verify_jwt(&jwt, &ec_pub(), &opts(Some("warden:test"), "agent:bot-7")).is_err());
    }

    #[test]
    fn hmac_token_rejected_alg_confusion() {
        // Attacker forges an HS256 token using the PUBLIC key bytes as the HMAC
        // secret. Asymmetric-only allowlist must reject it.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("k1".to_string());
        let key = EncodingKey::from_secret(EC_PUB.as_bytes());
        let forged = encode(&header, &claims_json(), &key).unwrap();
        assert!(verify_jwt(
            &forged,
            &DecodingKey::from_secret(EC_PUB.as_bytes()),
            &opts(Some("warden:test"), "agent:bot-7")
        )
        .is_err());
    }

    #[test]
    fn load_and_verify_jwt_from_pem_and_jwks_files() {
        // Exercises the real CLI path: read token + key from files, dispatch by
        // mode, verify. Token is signed by the fixture private key.
        let jwt = sign_es256(&claims_json(), "k1");
        let dir = std::env::temp_dir();
        let tok = dir.join("warden_test_token.jwt");
        let pem = dir.join("warden_test_pub.pem");
        std::fs::write(&tok, &jwt).unwrap();
        std::fs::write(&pem, EC_PUB).unwrap();

        // PEM mode
        let o = VerifyOpts {
            agent: "agent:bot-7".into(),
            expected_aud: Some("warden:test".into()),
            leeway: 60,
            pem_path: Some(pem.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let t = load_and_verify(tok.to_string_lossy().as_ref(), &o).unwrap();
        assert_eq!(t.claims.sub, "human:alice");
        assert!(t.signed);

        // JWKS mode (key matched by kid)
        let o = VerifyOpts {
            agent: "agent:bot-7".into(),
            expected_aud: Some("warden:test".into()),
            leeway: 60,
            jwks_path: Some(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/test_jwks.json").into()),
            ..Default::default()
        };
        let t = load_and_verify(tok.to_string_lossy().as_ref(), &o).unwrap();
        assert_eq!(t.claims.act_chain(), vec!["service:recon", "agent:bot-7"]);

        let _ = std::fs::remove_file(&tok);
        let _ = std::fs::remove_file(&pem);
    }

    // --- dev envelope path ---

    #[test]
    fn dev_envelope_signed_and_unsigned() {
        let v = claims_json();
        let claims: Claims = serde_json::from_value(v.clone()).unwrap();
        let mut o = VerifyOpts {
            agent: "agent:bot-7".into(),
            now: 1000,
            expected_aud: Some("warden:test".into()),
            ..Default::default()
        };
        // unsigned dev token (no key)
        assert!(verify_envelope(claims.clone(), None, &v, &o).is_ok());
        // signed dev token
        o.dev_key = Some("secret".into());
        let sig = sign(&v, "secret");
        assert!(verify_envelope(claims.clone(), Some(sig), &v, &o).is_ok());
        // wrong key
        assert!(verify_envelope(
            claims,
            Some(sign(&v, "secret")),
            &v,
            &VerifyOpts {
                dev_key: Some("other".into()),
                ..o
            }
        )
        .is_err());
    }
}
