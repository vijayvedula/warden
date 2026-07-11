"""warden-agent-sdk — build and sign canonical Warden delegation tokens, and route
agent frameworks through the Warden MCP proxy.

Two things, per the design (docs/platform-integration.md):

- **Identity adapters** shape a platform's native identity into Warden's
  canonical claims (``warden_sdk.adapters``).
- **Orchestration shims** point an agent framework's MCP client at
  ``warden proxy`` (``warden_sdk.orchestration``).

The proxy always accepts a raw conforming token with no SDK at all — this
package is convenience, not a new trust surface.
"""

from .canonical import canonical_json, dev_signature, sha256_hex
from .conformance import ConformanceResult, verify_jwt, verify_token
from .proxy import ProxyConfig
from .signing import JwtSigner
from .token import TokenBuilder

__all__ = [
    "TokenBuilder",
    "JwtSigner",
    "ProxyConfig",
    "canonical_json",
    "dev_signature",
    "sha256_hex",
    "verify_token",
    "verify_jwt",
    "ConformanceResult",
]

__version__ = "0.1.0"
