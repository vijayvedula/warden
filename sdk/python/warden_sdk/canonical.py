"""Canonical JSON — byte-for-byte compatible with Warden's ``util::canonical_json``.

The Rust proxy computes the dev-envelope signature over a canonical rendering of
the claims object: object keys sorted lexicographically, no insignificant
whitespace. Reproducing it exactly here is what lets a token this SDK signs
verify under ``warden token verify``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted object keys, compact separators.

    Mirrors serde_json rendering as used by Warden. Restrict values to JSON
    scalars (str/int/bool/None), lists, and dicts — the shape of a token's
    claims — so Python and Rust render identically.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def dev_signature(raw_claims: dict[str, Any], key: str) -> str:
    """The dev-envelope keyed digest: ``sha256_hex(f"{key}|{canonical}")``.

    Identical to Warden's ``identity::sign``. With no key, tokens are unsigned
    dev tokens (``signed = false`` at the proxy) — fine for local walkthroughs,
    never for enforcement.
    """
    return sha256_hex(f"{key}|{canonical_json(raw_claims)}")
