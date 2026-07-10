//! Minimal outbound HTTP for OIDC discovery + JWKS fetch (TLS via ureq).
//! Read-only GETs of public metadata; never sends secrets.

/// GET a URL and return the response body as text.
pub fn get_text(url: &str) -> Result<String, String> {
    let mut resp = ureq::get(url)
        .call()
        .map_err(|e| format!("http get {url}: {e}"))?;
    resp.body_mut()
        .read_to_string()
        .map_err(|e| format!("read {url}: {e}"))
}
