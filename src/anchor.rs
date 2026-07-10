//! External audit anchor: signed checkpoints of the chain head.
//!
//! The hash chain in [`crate::audit`] is tamper-evident only against an
//! attacker who *can't recompute it*. A writer who controls the log file can
//! rebuild every `row_hash`, or simply roll the log back (delete recent rows) --
//! a truncated prefix still verifies. To close that, Warden periodically signs
//! the current head `(seq, row_hash)` with a private key it alone holds and
//! appends the signature to a separate **anchor file**. Verification checks
//! each checkpoint's signature (with the public key) and that the referenced
//! head still matches the chain. A rewrite or rollback below a checkpoint is
//! then detectable, because the attacker cannot produce a valid signature.
//!
//! Checkpoints are ES256 JWTs (reusing the JWT crypto already in the build).
//! Ship the anchor file to append-only/WORM storage for full off-host
//! durability; that is an operational step, not code.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Debug, Serialize, Deserialize)]
struct Checkpoint {
    seq: u64,
    hash: String,
    ts: u64,
}

/// A loaded signing key for checkpoints (ES256).
pub struct Signer {
    key: EncodingKey,
}

impl Signer {
    pub fn from_ec_pem(pem: &[u8]) -> Result<Self, String> {
        let key = EncodingKey::from_ec_pem(pem).map_err(|e| format!("bad anchor key: {e}"))?;
        Ok(Signer { key })
    }

    fn sign(&self, seq: u64, hash: &str, ts: u64) -> Result<String, String> {
        let cp = Checkpoint {
            seq,
            hash: hash.to_string(),
            ts,
        };
        encode(&Header::new(Algorithm::ES256), &cp, &self.key)
            .map_err(|e| format!("sign checkpoint: {e}"))
    }

    /// Append a signed checkpoint of the head to the anchor file.
    pub fn append_checkpoint(
        &self,
        anchor_path: &str,
        seq: u64,
        hash: &str,
        ts: u64,
    ) -> Result<(), String> {
        let jwt = self.sign(seq, hash, ts)?;
        if let Some(parent) = std::path::Path::new(anchor_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(anchor_path)
            .map_err(|e| format!("open anchor: {e}"))?;
        writeln!(file, "{jwt}").map_err(|e| format!("write anchor: {e}"))
    }
}

/// Verify every checkpoint in the anchor file: signature valid, and the
/// referenced `(seq, hash)` still matches the chain. `head_by_seq` maps each
/// entry's seq to its `row_hash`. Returns the number of checkpoints verified.
pub fn verify(
    anchor_path: &str,
    pub_pem: &[u8],
    head_by_seq: &HashMap<u64, String>,
) -> Result<usize, String> {
    let text = std::fs::read_to_string(anchor_path).map_err(|e| format!("read anchor: {e}"))?;
    let key = DecodingKey::from_ec_pem(pub_pem).map_err(|e| format!("bad anchor pubkey: {e}"))?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;

    let mut count = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let data = decode::<Checkpoint>(line, &key, &validation)
            .map_err(|e| format!("checkpoint signature invalid: {e}"))?;
        let cp = data.claims;
        match head_by_seq.get(&cp.seq) {
            None => {
                return Err(format!(
                    "rollback detected: checkpoint for seq {} but the log has no such entry",
                    cp.seq
                ))
            }
            Some(h) if h != &cp.hash => {
                return Err(format!(
                    "rewrite detected: seq {} hash does not match the signed checkpoint",
                    cp.seq
                ))
            }
            Some(_) => count += 1,
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV: &str = include_str!("../fixtures/test_ec_priv.pem");
    const PUB: &str = include_str!("../fixtures/test_ec_pub.pem");

    #[test]
    fn checkpoint_roundtrip_and_tamper() {
        let dir = std::env::temp_dir();
        let path = dir.join("warden_anchor_test.jsonl");
        let _ = std::fs::remove_file(&path);
        let p = path.to_string_lossy();
        let signer = Signer::from_ec_pem(PRIV.as_bytes()).unwrap();
        signer.append_checkpoint(&p, 1, "hashA", 100).unwrap();
        signer.append_checkpoint(&p, 2, "hashB", 200).unwrap();

        // Honest chain: seq->hash matches the signed checkpoints.
        let mut head: HashMap<u64, String> = HashMap::new();
        head.insert(1, "hashA".into());
        head.insert(2, "hashB".into());
        assert_eq!(verify(&p, PUB.as_bytes(), &head).unwrap(), 2);

        // Rollback: seq 2 removed -> detected.
        let mut rolled = HashMap::new();
        rolled.insert(1, "hashA".into());
        assert!(verify(&p, PUB.as_bytes(), &rolled).is_err());

        // Rewrite: seq 2 hash changed -> detected.
        let mut rewritten = HashMap::new();
        rewritten.insert(1, "hashA".into());
        rewritten.insert(2, "EVIL".into());
        assert!(verify(&p, PUB.as_bytes(), &rewritten).is_err());

        let _ = std::fs::remove_file(&path);
    }
}
