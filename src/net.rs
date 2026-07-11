//! Minimal outbound HTTP for OIDC discovery + JWKS fetch (TLS via ureq).
//! Read-only GETs of public metadata; never sends secrets.
//!
//! Hardening: the target is (indirectly) issuer-controlled -- a discovery doc
//! can point `jwks_uri` anywhere -- so this path is treated as semi-trusted.
//! We require `https` (no plaintext / no `http://169.254.169.254`-style
//! metadata SSRF), bound connect/read time, cap the redirect chain, and limit
//! the body size so a hostile or hung endpoint can't hang or OOM the proxy.

use std::time::Duration;

const FETCH_TIMEOUT_SECS: u64 = 10;
const MAX_REDIRECTS: u32 = 3;
const MAX_BODY_BYTES: u64 = 2 * 1024 * 1024;

/// GET an `https` URL and return the response body as text (bounded).
pub fn get_text(url: &str) -> Result<String, String> {
    // Enforce TLS: blocks plaintext fetches and the classic link-local metadata
    // SSRF (`http://169.254.169.254/...`). Redirects are also capped below.
    if !url
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("https://")
    {
        return Err(format!("refusing non-https metadata URL: {url}"));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(FETCH_TIMEOUT_SECS)))
        .max_redirects(MAX_REDIRECTS)
        .build()
        .into();
    let mut resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("http get {url}: {e}"))?;
    resp.body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .read_to_string()
        .map_err(|e| format!("read {url}: {e}"))
}
