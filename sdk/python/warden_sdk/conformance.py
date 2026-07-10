"""Conformance kit — prove a token this SDK builds verifies under Warden.

The moat is the token spec + the proxy's verifier. An adapter is *conformant*
iff the token it emits passes ``warden token verify`` — the exact check the proxy
runs before forwarding a call. This module shells out to the real binary so
first-party and community adapters are verifiable against ground truth, not a
Python re-implementation.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass


class WardenBinaryNotFound(RuntimeError):
    pass


def find_warden(explicit: str | None = None) -> str:
    """Locate the ``warden`` binary: explicit arg, ``$WARDEN_BIN``, or PATH."""
    candidate = explicit or os.environ.get("WARDEN_BIN") or shutil.which("warden")
    if not candidate or not os.path.exists(candidate):
        raise WardenBinaryNotFound(
            "warden binary not found; set WARDEN_BIN, pass warden_bin=..., or "
            "put `warden` on PATH (cargo build --release)"
        )
    return candidate


@dataclass
class ConformanceResult:
    ok: bool
    output: str
    returncode: int

    def raise_for_status(self) -> ConformanceResult:
        if not self.ok:
            raise AssertionError(f"token failed Warden conformance:\n{self.output}")
        return self


def verify_token(
    envelope: dict,
    *,
    agent: str,
    audience: str | None = None,
    issuer: str | None = None,
    token_key: str | None = None,
    warden_bin: str | None = None,
) -> ConformanceResult:
    """Write ``envelope`` to a temp file and run ``warden token verify`` on it.

    This is the dev-envelope path (no crypto deps). For a keyed dev envelope pass
    the same ``token_key`` used to sign it. Returns a :class:`ConformanceResult`;
    call ``.raise_for_status()`` to turn a failure into an assertion.
    """
    binary = find_warden(warden_bin)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "token.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(envelope, f)
        cmd = [binary, "token", "verify", "--token", path, "--agent", agent]
        if audience:
            cmd += ["--aud", audience]
        if issuer:
            cmd += ["--iss", issuer]
        if token_key:
            cmd += ["--token-key", token_key]
        proc = subprocess.run(cmd, capture_output=True, text=True)
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return ConformanceResult(ok=proc.returncode == 0, output=output, returncode=proc.returncode)


def verify_jwt(
    compact_jwt: str,
    *,
    agent: str,
    issuer_key_pem_path: str,
    audience: str | None = None,
    issuer: str | None = None,
    at_jwt: bool = False,
    warden_bin: str | None = None,
) -> ConformanceResult:
    """Verify a compact JWT against an issuer PEM public key via the proxy."""
    binary = find_warden(warden_bin)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "token.jwt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(compact_jwt)
        cmd = [
            binary, "token", "verify",
            "--token", path,
            "--agent", agent,
            "--issuer-key", issuer_key_pem_path,
        ]
        if audience:
            cmd += ["--aud", audience]
        if issuer:
            cmd += ["--iss", issuer]
        if at_jwt:
            cmd += ["--require-at-jwt"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return ConformanceResult(ok=proc.returncode == 0, output=output, returncode=proc.returncode)
