"""
FIDO2 / WebAuthn endpoints — credential enrollment and signing ceremony.

Registration flow  (pre-exhibition, one-time per analyst):
  POST /api/auth/register/begin    → PublicKeyCredentialCreationOptions + session_id
  POST /api/auth/register/complete → store AttestedCredentialData in DB

Signing flow  (live remediation approval):
  POST /api/auth/sign/begin → PublicKeyCredentialRequestOptions + session_id
  (assertion response is submitted directly to /api/verify-remediation)
"""

import base64
import dataclasses
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.challenge_store import pop, put
from auth.fido2_rp import RP_ORIGIN, fido2_server
from db.database import AsyncSessionLocal
from db.models import WebAuthnCredential

router = APIRouter(prefix="/api/auth", tags=["fido2"])


# ── DB session ────────────────────────────────────────────────────────────────

async def _get_session():
    async with AsyncSessionLocal() as session:
        yield session


# ── Request / Response schemas ────────────────────────────────────────────────

class RegisterBeginRequest(BaseModel):
    user_id:   str
    user_name: str

class RegisterCompleteRequest(BaseModel):
    session_id: str
    credential: dict   # PublicKeyCredential JSON from navigator.credentials.create()

class SignBeginRequest(BaseModel):
    user_id:           str
    stark_receipt_b64: str   # receipt hash is bound to this session
    mock_fido2:        bool = False

class ListCredentialsResponse(BaseModel):
    credentials: list[dict]


# ── Registration ceremony ─────────────────────────────────────────────────────

@router.post("/register/begin")
async def register_begin(
    req: RegisterBeginRequest,
    session: AsyncSession = Depends(_get_session),
):
    """
    Start a WebAuthn registration ceremony.
    Returns PublicKeyCredentialCreationOptions for navigator.credentials.create().
    """
    from fido2.webauthn import PublicKeyCredentialUserEntity

    # Load any existing credentials for this user so the authenticator excludes
    # them (prevents registering the same key twice).
    rows = (await session.execute(
        select(WebAuthnCredential).where(WebAuthnCredential.user_id == req.user_id)
    )).scalars().all()
    existing = _load_credentials(rows)

    options, state = fido2_server.register_begin(
        user=PublicKeyCredentialUserEntity(
            id=req.user_id.encode(),
            name=req.user_name,
            display_name=req.user_name,
        ),
        credentials=existing,
        user_verification="discouraged",    # hardware key — no PIN required for demo
    )

    session_id = str(uuid.uuid4())
    await put(session_id, {"fido2_state": state, "user_id": req.user_id, "user_name": req.user_name})

    return {"session_id": session_id, "options": _to_json(options), "rp_origin": RP_ORIGIN}


@router.post("/register/complete")
async def register_complete(
    req: RegisterCompleteRequest,
    session: AsyncSession = Depends(_get_session),
):
    """
    Complete registration: verify attestation and persist the credential.
    """
    bundle = await pop(req.session_id)
    if bundle is None:
        raise HTTPException(400, "Challenge expired or unknown session_id")

    state     = bundle["fido2_state"]
    user_id   = bundle["user_id"]
    user_name = bundle["user_name"]

    if req.credential.get("mock_fido2"):
        # Bypass normal FIDO2 library verification for the software mock
        cred_id = "mock-cred-id-1234"
        row = WebAuthnCredential(
            credential_id=cred_id,
            user_id=user_id,
            user_name=user_name,
            attested_cred_cbor=b"mock_cbor_data",  # dummy data
            sign_count=0,
            registered_at=datetime.now(tz=timezone.utc),
        )
        session.add(row)
        await session.commit()
        return {"success": True, "credential_id": cred_id, "user_id": user_id}

    try:
        auth_data = fido2_server.register_complete(state, req.credential)
    except Exception as exc:
        raise HTTPException(400, f"Attestation verification failed: {exc}") from exc

    cred      = auth_data.credential_data
    cred_id   = base64.b64encode(cred.credential_id).decode()

    row = WebAuthnCredential(
        credential_id=cred_id,
        user_id=user_id,
        user_name=user_name,
        attested_cred_cbor=bytes(cred),    # full AttestedCredentialData wire bytes
        sign_count=0,
        registered_at=datetime.now(tz=timezone.utc),
    )
    session.add(row)
    await session.commit()

    return {"success": True, "credential_id": cred_id, "user_id": user_id}


# ── Signing (assertion) ceremony ──────────────────────────────────────────────

@router.post("/sign/begin")
async def sign_begin(
    req: SignBeginRequest,
    session: AsyncSession = Depends(_get_session),
):
    """
    Generate a WebAuthn authentication challenge.
    The session state binds this challenge to req.stark_receipt_b64, so
    /api/verify-remediation can confirm the analyst signed off on the exact
    STARK receipt being submitted.
    """
    import hashlib

    receipt_hash = hashlib.sha256(req.stark_receipt_b64.encode()).hexdigest()
    session_id   = str(uuid.uuid4())

    if req.mock_fido2:
        # Software mock — skip hardware key ceremony entirely.
        # The verify-remediation endpoint checks bundle["mock_fido2"] to bypass WebAuthn.
        await put(session_id, {
            "fido2_state":  None,
            "receipt_hash": receipt_hash,
            "mock_fido2":   True,
        })
        return {"session_id": session_id, "options": None, "mock_fido2": True}

    rows = (await session.execute(
        select(WebAuthnCredential).where(WebAuthnCredential.user_id == req.user_id)
    )).scalars().all()
    if not rows:
        raise HTTPException(404, "No registered credentials for this user — enroll a key first")

    credentials = _load_credentials(rows)
    options, state = fido2_server.authenticate_begin(
        credentials=credentials,
        user_verification="discouraged",
    )

    await put(session_id, {"fido2_state": state, "receipt_hash": receipt_hash})
    return {"session_id": session_id, "options": _to_json(options)}


# ── Credential list ───────────────────────────────────────────────────────────

@router.get("/credentials/{user_id}", response_model=ListCredentialsResponse)
async def list_credentials(
    user_id: str,
    session: AsyncSession = Depends(_get_session),
):
    rows = (await session.execute(
        select(WebAuthnCredential).where(WebAuthnCredential.user_id == user_id)
    )).scalars().all()
    return {"credentials": [
        {"credential_id": r.credential_id, "user_name": r.user_name,
         "sign_count": r.sign_count, "registered_at": r.registered_at.isoformat()}
        for r in rows
    ]}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_credentials(rows: list[WebAuthnCredential]):
    """Reconstruct AttestedCredentialData objects from DB rows."""
    from fido2.webauthn import AttestedCredentialData
    return [AttestedCredentialData(row.attested_cred_cbor) for row in rows]


def _to_json(obj: Any) -> Any:
    """
    Recursively convert a fido2 options object (dataclass tree) to a
    JSON-serialisable dict, encoding bytes as base64url and Enums as values.
    """
    if isinstance(obj, bytes):
        return base64.urlsafe_b64encode(obj).rstrip(b"=").decode()
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        # dataclasses.asdict() recurses into nested dataclasses automatically
        return _to_json(dataclasses.asdict(obj))
    if isinstance(obj, dict):
        return {k: _to_json(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, (list, tuple)):
        return [_to_json(i) for i in obj if i is not None]
    return obj
