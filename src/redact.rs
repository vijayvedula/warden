//! Regulation-aware PII / secret redaction for recorded & exported data.
//!
//! Tool arguments can carry personal data and secrets. Warden **executes** the
//! real arguments (the forwarded call is untouched) but **records and exports a
//! redacted projection** -- supporting data-minimisation (GDPR Art. 5(1)(c)) and
//! keeping PII out of the audit chain / SIEM / SSF.
//!
//! Configurable by **profile** (regulation) so operators redact what *their*
//! regime requires:
//!
//! - `gdpr` -- personal + special-category (Art. 9) + online identifiers
//! - `ccpa` -- personal identifiers
//! - `hipaa` -- PHI identifiers (health + safe-harbor classes)
//! - `pci` -- cardholder data (PAN, IBAN, CVV)
//! - `secrets` -- credentials / tokens / keys
//! - `all` -- every class
//!
//! Plus custom `--redact-fields` and optional value scanning
//! (`--redact-scan-values`). Detection is by **field name** (reliable) and,
//! optionally, by **value pattern** (catches PII in mis-named fields).
//! Redaction preserves JSON structure: a value becomes `"[REDACTED:<class>]"`.

use serde_json::{Map, Value};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Email,
    Phone,
    Name,
    Dob,
    Address,
    NationalId,
    CreditCard,
    Iban,
    Ip,
    Health,
    Biometric,
    Secret,
}

impl Class {
    fn label(self) -> &'static str {
        match self {
            Class::Email => "email",
            Class::Phone => "phone",
            Class::Name => "name",
            Class::Dob => "dob",
            Class::Address => "address",
            Class::NationalId => "national_id",
            Class::CreditCard => "credit_card",
            Class::Iban => "iban",
            Class::Ip => "ip",
            Class::Health => "health",
            Class::Biometric => "biometric",
            Class::Secret => "secret",
        }
    }

    fn keywords(self) -> &'static [&'static str] {
        match self {
            Class::Email => &["email", "e_mail", "mail"],
            Class::Phone => &["phone", "mobile", "tel", "msisdn"],
            Class::Name => &[
                "first_name",
                "last_name",
                "full_name",
                "fname",
                "lname",
                "surname",
                "given_name",
                "middle_name",
            ],
            Class::Dob => &["dob", "birthdate", "date_of_birth", "birth"],
            Class::Address => &["address", "street", "postal", "postcode", "zipcode", "zip"],
            Class::NationalId => &[
                "ssn",
                "social_security",
                "passport",
                "national_id",
                "nin",
                "aadhaar",
                "tax_id",
                "drivers_license",
            ],
            Class::CreditCard => &[
                "card_number",
                "cc_number",
                "credit_card",
                "pan",
                "cvv",
                "cvc",
            ],
            Class::Iban => &[
                "iban",
                "bank_account",
                "account_number",
                "routing",
                "sort_code",
            ],
            Class::Ip => &["ip_address", "ipaddr", "client_ip", "ip"],
            Class::Health => &[
                "diagnosis",
                "health",
                "medical",
                "icd",
                "condition",
                "prescription",
                "treatment",
            ],
            Class::Biometric => &[
                "biometric",
                "fingerprint",
                "faceprint",
                "dna",
                "genetic",
                "retina",
            ],
            Class::Secret => &[
                "password",
                "passwd",
                "pwd",
                "secret",
                "token",
                "api_key",
                "apikey",
                "access_key",
                "secret_key",
                "private_key",
                "credential",
                "authorization",
                "auth_token",
                "session_key",
            ],
        }
    }
}

fn profile_classes(p: &str) -> Vec<Class> {
    use Class::*;
    match p.trim() {
        "gdpr" => vec![
            Email, Phone, Name, Dob, Address, NationalId, Ip, Health, Biometric,
        ],
        "ccpa" => vec![Email, Phone, Name, Dob, Address, NationalId, Ip],
        "hipaa" => vec![Name, Dob, Address, Phone, Email, NationalId, Health],
        "pci" => vec![CreditCard, Iban],
        "secrets" => vec![Secret],
        "all" => vec![
            Email, Phone, Name, Dob, Address, NationalId, CreditCard, Iban, Ip, Health, Biometric,
            Secret,
        ],
        _ => vec![],
    }
}

pub struct Redactor {
    enabled: bool,
    classes: Vec<Class>,
    extra_fields: Vec<String>,
    scan_values: bool,
}

impl Redactor {
    pub fn disabled() -> Self {
        Redactor {
            enabled: false,
            classes: Vec::new(),
            extra_fields: Vec::new(),
            scan_values: false,
        }
    }

    /// Build from a comma-separated profile list, extra field keywords, and
    /// whether to scan string values (not just field names).
    pub fn from_config(profiles: &str, extra_fields: &str, scan_values: bool) -> Self {
        let mut classes: Vec<Class> = Vec::new();
        for p in profiles.split(',') {
            for c in profile_classes(p) {
                if !classes.contains(&c) {
                    classes.push(c);
                }
            }
        }
        let extra: Vec<String> = extra_fields
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        Redactor {
            enabled: !classes.is_empty() || !extra.is_empty(),
            classes,
            extra_fields: extra,
            scan_values,
        }
    }

    fn key_label(&self, key: &str) -> Option<&'static str> {
        let lower = key.to_ascii_lowercase();
        for c in &self.classes {
            if c.keywords().iter().any(|kw| lower.contains(kw)) {
                return Some(c.label());
            }
        }
        if self.extra_fields.iter().any(|f| lower.contains(f)) {
            return Some("custom");
        }
        None
    }

    fn value_label(&self, s: &str) -> Option<&'static str> {
        if !self.scan_values {
            return None;
        }
        if is_email(s) {
            return Some("email");
        }
        if is_ssn(s) {
            return Some("national_id");
        }
        if is_credit_card(s) {
            return Some("credit_card");
        }
        if is_ipv4(s) {
            return Some("ip");
        }
        None
    }

    /// Return a redacted clone (structure preserved). No-op when disabled.
    pub fn redact(&self, v: &Value) -> Value {
        if !self.enabled {
            return v.clone();
        }
        match v {
            Value::Object(m) => {
                let mut out = Map::new();
                for (k, val) in m {
                    if let Some(label) = self.key_label(k) {
                        out.insert(k.clone(), Value::String(format!("[REDACTED:{label}]")));
                    } else {
                        out.insert(k.clone(), self.redact(val));
                    }
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(|x| self.redact(x)).collect()),
            Value::String(s) => match self.value_label(s) {
                Some(label) => Value::String(format!("[REDACTED:{label}]")),
                None => v.clone(),
            },
            _ => v.clone(),
        }
    }
}

// --- value detectors (dependency-free) ---

fn is_email(s: &str) -> bool {
    let parts: Vec<&str> = s.split('@').collect();
    parts.len() == 2
        && !parts[0].is_empty()
        && parts[1].contains('.')
        && !s.chars().any(|c| c.is_whitespace())
        && s.len() >= 5
}

fn is_ssn(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 11
        && b.iter().enumerate().all(|(i, &c)| {
            if i == 3 || i == 6 {
                c == b'-'
            } else {
                c.is_ascii_digit()
            }
        })
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

fn is_credit_card(s: &str) -> bool {
    if s.chars()
        .any(|c| !(c.is_ascii_digit() || c == ' ' || c == '-'))
    {
        return false;
    }
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut d = d;
        if alt {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn gdpr_and_secrets_redact_keeps_structure() {
        let r = Redactor::from_config("gdpr,secrets", "", true);
        let v = json!({
            "to": "alice@example.com",          // value-scan -> email
            "amount": 50,                        // kept
            "password": "hunter2",               // key -> secret
            "nested": { "ssn": "123-45-6789" },  // key -> national_id
            "note": "ring me later"              // kept
        });
        let out = r.redact(&v);
        assert_eq!(out["to"], "[REDACTED:email]");
        assert_eq!(out["amount"], 50);
        assert_eq!(out["password"], "[REDACTED:secret]");
        assert_eq!(out["nested"]["ssn"], "[REDACTED:national_id]");
        assert_eq!(out["note"], "ring me later");
    }

    #[test]
    fn pci_redacts_card_value() {
        let r = Redactor::from_config("pci", "", true);
        let out = r.redact(&json!({ "x": "4111 1111 1111 1111" })); // Luhn-valid test PAN
        assert_eq!(out["x"], "[REDACTED:credit_card]");
    }

    #[test]
    fn custom_field_and_disabled() {
        let r = Redactor::from_config("", "internal_ref", false);
        assert_eq!(
            r.redact(&json!({ "internal_ref": "x" }))["internal_ref"],
            "[REDACTED:custom]"
        );
        let off = Redactor::disabled();
        let v = json!({ "email": "a@b.com" });
        assert_eq!(off.redact(&v), v);
    }
}
