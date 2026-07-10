//! Transaction Tokens (IETF OAuth WG / WIMSE) -- immutable call context that
//! propagates across agent hops.
//!
//! When Warden authorizes an action it can mint a short-lived **Txn-Token**: a
//! signed JWT carrying the transaction id, the accountable subject, the
//! authorization details (`azd`), and the requester context (`rctx`, the act
//! chain). As the call fans out to other agents (A2A), each hop forwards the
//! token; the next Warden `verify`s it and `extend`s the chain by one actor --
//! so multi-hop accountability survives across services without re-minting
//! authority. ES256, reusing the existing JWT crypto.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxnClaims {
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    /// Stable transaction id, immutable across the whole call chain.
    pub txn: String,
    /// Accountable subject (the human).
    pub sub: String,
    /// Purpose of the transaction.
    pub purp: String,
    /// Authorization details: the action that was permitted.
    pub azd: Azd,
    /// Requester context: the acting chain so far.
    pub rctx: Rctx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Azd {
    pub action: String,
    pub resource: String,
    pub decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rctx {
    pub act_chain: Vec<String>,
}

/// Mint a Txn-Token (ES256).
#[allow(clippy::too_many_arguments)]
pub fn mint(
    key_pem: &[u8],
    iss: &str,
    txn: &str,
    sub: &str,
    action: &str,
    resource: &str,
    act_chain: &[String],
    now: u64,
    ttl: u64,
) -> Result<String, String> {
    let key = EncodingKey::from_ec_pem(key_pem).map_err(|e| format!("bad txn key: {e}"))?;
    let claims = TxnClaims {
        iss: iss.to_string(),
        iat: now,
        exp: now + ttl,
        jti: format!("txn-{txn}-{now}"),
        txn: txn.to_string(),
        sub: sub.to_string(),
        purp: "agent-action".to_string(),
        azd: Azd {
            action: action.to_string(),
            resource: resource.to_string(),
            decision: "allow".to_string(),
        },
        rctx: Rctx {
            act_chain: act_chain.to_vec(),
        },
    };
    encode(&Header::new(Algorithm::ES256), &claims, &key).map_err(|e| format!("mint txn: {e}"))
}

/// Verify an inbound Txn-Token (ES256) -- for the next A2A hop.
#[allow(dead_code)] // consumed by the downstream A2A hop; covered by tests
pub fn verify(jwt: &str, pub_pem: &[u8], now: u64, leeway: u64) -> Result<TxnClaims, String> {
    let key = DecodingKey::from_ec_pem(pub_pem).map_err(|e| format!("bad txn pubkey: {e}"))?;
    let mut v = Validation::new(Algorithm::ES256);
    v.required_spec_claims.clear();
    v.leeway = leeway;
    v.validate_exp = true;
    v.validate_aud = false;
    let _ = now; // exp validated against system time by the library
    decode::<TxnClaims>(jwt, &key, &v)
        .map(|d| d.claims)
        .map_err(|e| format!("txn verify failed: {e}"))
}

/// Extend a verified Txn-Token by one actor for the next hop (same `txn`).
#[allow(clippy::too_many_arguments, dead_code)] // A2A hop; covered by tests
pub fn extend(
    key_pem: &[u8],
    parent: &TxnClaims,
    next_actor: &str,
    action: &str,
    resource: &str,
    now: u64,
    ttl: u64,
) -> Result<String, String> {
    let mut chain = parent.rctx.act_chain.clone();
    chain.push(next_actor.to_string());
    mint(
        key_pem,
        &parent.iss,
        &parent.txn,
        &parent.sub,
        action,
        resource,
        &chain,
        now,
        ttl,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV: &str = include_str!("../fixtures/test_ec_priv.pem");
    const PUB: &str = include_str!("../fixtures/test_ec_pub.pem");

    #[test]
    fn mint_verify_and_extend_chain() {
        let far = 4_102_444_800; // year 2100
        let jwt = mint(
            PRIV.as_bytes(),
            "warden",
            "T1",
            "human:alice",
            "wire_funds",
            "account:123",
            &["svc".into(), "agent:a".into()],
            far - 60,
            60,
        )
        .unwrap();
        let c = verify(&jwt, PUB.as_bytes(), 0, 60).unwrap();
        assert_eq!(c.txn, "T1");
        assert_eq!(c.sub, "human:alice");
        assert_eq!(c.azd.action, "wire_funds");
        assert_eq!(c.rctx.act_chain, vec!["svc", "agent:a"]);

        // Next A2A hop extends the chain, same txn.
        let child = extend(
            PRIV.as_bytes(),
            &c,
            "agent:b",
            "read_file",
            "doc:1",
            far - 30,
            60,
        )
        .unwrap();
        let c2 = verify(&child, PUB.as_bytes(), 0, 60).unwrap();
        assert_eq!(c2.txn, "T1");
        assert_eq!(c2.rctx.act_chain, vec!["svc", "agent:a", "agent:b"]);
    }

    #[test]
    fn expired_txn_rejected() {
        let jwt = mint(PRIV.as_bytes(), "warden", "T2", "h", "a", "r", &[], 1, 1).unwrap();
        assert!(verify(&jwt, PUB.as_bytes(), 0, 0).is_err());
    }
}
