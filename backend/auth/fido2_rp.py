"""
FIDO2 Relying Party singleton — bound to omniwatch.local.

WebAuthn mandates a secure context (HTTPS) and a registerable RP ID.
FIDO2_RP_ID  : the domain registered in the authenticator (must match the TLS cert CN).
FIDO2_ORIGIN : the exact origin the browser presents — must equal https://{RP_ID}
               (or https://{RP_ID}:{PORT} if not on 443, in which case override via env).

Environment variables:
  FIDO2_RP_ID   default: "omniwatch.local"
  FIDO2_ORIGIN  default: "https://omniwatch.local"
"""

import os

from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

RP_ID:     str = os.getenv("FIDO2_RP_ID",   "omniwatch.local")
RP_NAME:   str = os.getenv("FIDO2_RP_NAME", "OmniWatch SOC")
RP_ORIGIN: str = os.getenv("FIDO2_ORIGIN",  f"https://{RP_ID}")

_rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)

# verify_origin=None → fido2 defaults to accepting exactly "https://{RP_ID}".
# Override with a custom lambda when the origin includes a non-standard port.
_verify_origin = None
if ":" in RP_ORIGIN.split("//", 1)[-1]:
    # Non-standard port — fido2's default check would reject it; provide explicit check.
    _verify_origin = lambda origin: origin == RP_ORIGIN   # noqa: E731

fido2_server = Fido2Server(_rp, verify_origin=_verify_origin)
