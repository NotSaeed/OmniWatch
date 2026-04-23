import json
import uuid
import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential

from db.database import AsyncSessionLocal
from db.models import User, WebAuthnCredential, SpentReceipt

router = APIRouter()
logger = logging.getLogger(__name__)

RP_ID = "localhost" # or "omniwatch.local" based on architecture
RP_NAME = "OmniWatch"
ORIGIN = "http://localhost:5173"

async def get_session():
    async with AsyncSessionLocal() as session:
        yield session

class RegisterRequest(BaseModel):
    username: str

class VerifyRegRequest(BaseModel):
    username: str
    response: dict

class AuthRequest(BaseModel):
    username: str
    nonce: str # the STARK receipt nonce

class VerifyAuthRequest(BaseModel):
    username: str
    nonce: str
    response: dict
    target_ip: str | None = None
    label: str | None = None

@router.post("/api/webauthn/register-options")
async def register_options(req: RegisterRequest, session: AsyncSession = Depends(get_session)):
    import sqlalchemy as sa
    user = (await session.execute(sa.select(User).where(User.username == req.username))).scalar()
    if not user:
        user = User(id=str(uuid.uuid4()), username=req.username)
        session.add(user)
    
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user.id.encode(),
        user_name=req.username,
    )
    user.current_challenge = options.challenge.hex()
    await session.commit()
    return json.loads(options.json()) # Return to frontend

@router.post("/api/webauthn/register-verify")
async def register_verify(req: VerifyRegRequest, session: AsyncSession = Depends(get_session)):
    import sqlalchemy as sa
    user = (await session.execute(sa.select(User).where(User.username == req.username))).scalar()
    if not user or not user.current_challenge:
        raise HTTPException(400, "Challenge not found")
        
    try:
        verification = verify_registration_response(
            credential=req.response,
            expected_challenge=bytes.fromhex(user.current_challenge),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=False,
        )
        
        cred = WebAuthnCredential(
            id=verification.credential_id.hex(),
            user_id=user.id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count
        )
        session.add(cred)
        user.current_challenge = None
        await session.commit()
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"FIDO2 verify failed: {e}")
        raise HTTPException(400, "Registration failed")

@router.post("/api/webauthn/auth-options")
async def auth_options(req: AuthRequest, session: AsyncSession = Depends(get_session)):
    import sqlalchemy as sa
    user = (await session.execute(sa.select(User).where(User.username == req.username))).scalar()
    if not user:
        raise HTTPException(404, "User not found")
        
    # Phase 4 Nonce Registry check
    spent = (await session.execute(sa.select(SpentReceipt).where(SpentReceipt.nonce == req.nonce))).scalar()
    if spent:
        raise HTTPException(400, "Receipt replay attack detected")
        
    options = generate_authentication_options(
        rp_id=RP_ID,
        challenge=req.nonce.encode(), # bind the cryptographic challenge to the STARK nonce
    )
    user.current_challenge = options.challenge.hex()
    await session.commit()
    return json.loads(options.json())

@router.post("/api/webauthn/auth-verify")
async def auth_verify(req: VerifyAuthRequest, session: AsyncSession = Depends(get_session)):
    import sqlalchemy as sa
    user = (await session.execute(sa.select(User).where(User.username == req.username))).scalar()
    if not user:
        raise HTTPException(404, "User not found")
        
    cred_id = req.response.get("id")
    cred = (await session.execute(sa.select(WebAuthnCredential).where(WebAuthnCredential.id == cred_id))).scalar()
    if not cred:
        raise HTTPException(404, "Credential not found")
        
    try:
        verification = verify_authentication_response(
            credential=req.response,
            expected_challenge=bytes.fromhex(user.current_challenge),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=cred.public_key,
            credential_current_sign_count=cred.sign_count,
        )
        cred.sign_count = verification.new_sign_count
        
        # Insert spent receipt to prevent replay
        spent = SpentReceipt(nonce=req.nonce)
        session.add(spent)
        user.current_challenge = None
        await session.commit()
        
        # Execute SOAR Playbook if requested
        if req.target_ip and req.label:
            from services.soar_engine import execute_pending_playbook
            from ingestion.cicids_parser import _db_path
            execute_pending_playbook(_db_path(), req.target_ip, req.label)
            
        return {"status": "ok", "message": "Cryptographic Oversite Proof valid. Receipt Executed"}
    except Exception as e:
        logger.error(f"FIDO2 verify failed: {e}")
        raise HTTPException(400, "Verification failed")
