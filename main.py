"""
Access Control System - Backend API
FastAPI + PostgreSQL + Ed25519 Signatures
"""

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from datetime import datetime, timedelta
from typing import Optional, List
import os
import json
import base64
import secrets
import time
from jose import jwt, JWTError
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder

from models import (
    Base, User, Device, Community, Membership, Event, Keyset, NonceSeen,
    RegisterDeviceRequest, SignTokenRequest, SignTokenResponse,
    CommunityResponse, EventResponse, AdminLoginRequest,
    ApproveRequest, MembershipResponse, PiConfigResponse,
    PiEventRequest, CreateCommunityRequest
)

# Configuration from environment
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./access_control.db")
JWT_SECRET = os.getenv("JWT_SECRET", "your-super-secret-key")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI(title="Access Control API", version="1.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Auth helpers
def generate_admin_token(username: str) -> str:
    expires = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expires}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def create_signed_token(
    user_id: str,
    device_id: str,
    community_id: str,
    event_type: str,
    private_key_b64: str
) -> tuple:
    now = int(time.time())
    expires = now + 30
    nonce = secrets.token_hex(12)
    
    payload = {
        "ver": 1,
        "user_id": user_id,
        "device_id": device_id,
        "community_id": community_id,
        "type": event_type,
        "iat": now,
        "exp": expires,
        "nonce": nonce
    }
    
    payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    
    signing_key = SigningKey(private_key_b64, encoder=Base64Encoder)
    signed = signing_key.sign(payload_bytes)
    signature = signed.signature
    
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode().rstrip('=')
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    token = f"{payload_b64}.{sig_b64}"
    return token, expires

# PUBLIC ENDPOINTS

@app.get("/")
def root():
    return {"message": "Access Control API", "version": "1.0", "status": "running"}

@app.post("/register_device")
def register_device(req: RegisterDeviceRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == req.user_id).first()
    if not user:
        user = User(user_id=req.user_id, phone=req.phone)
        db.add(user)
    
    device = db.query(Device).filter(Device.device_id == req.device_id).first()
    if not device:
        device = Device(device_id=req.device_id, user_id=req.user_id, platform=req.platform)
        db.add(device)
    
    existing = db.query(Membership).filter(
        Membership.user_id == req.user_id,
        Membership.community_id == req.community_id
    ).first()
    
    if not existing:
        membership = Membership(user_id=req.user_id, community_id=req.community_id, status="pending")
        db.add(membership)
    
    db.commit()
    
    return {
        "success": True,
        "message": "Registration submitted",
        "status": existing.status if existing else "pending"
    }

@app.get("/my_communities")
def get_my_communities(x_device_id: str = Header(...), db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.device_id == x_device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    memberships = db.query(Membership, Community).join(
        Community, Membership.community_id == Community.community_id
    ).filter(
        Membership.user_id == device.user_id,
        Membership.status == "approved"
    ).all()
    
    return [
        CommunityResponse(
            community_id=comm.community_id,
            name=comm.name,
            description=comm.description,
            status=mem.status
        )
        for mem, comm in memberships
    ]

@app.post("/sign_token")
def sign_token(req: SignTokenRequest, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.device_id == req.device_id).first()
    if not device or device.user_id != req.user_id:
        raise HTTPException(status_code=403, detail="Device not authorized")
    
    membership = db.query(Membership).filter(
        Membership.user_id == req.user_id,
        Membership.community_id == req.community_id,
        Membership.status == "approved"
    ).first()
    
    if not membership:
        raise HTTPException(status_code=403, detail="Not approved for this community")
    
    keyset = db.query(Keyset).filter(
        Keyset.community_id == req.community_id,
        Keyset.active == True
    ).first()
    
    if not keyset:
        raise HTTPException(status_code=500, detail="No active keyset")
    
    token, expires_at = create_signed_token(
        req.user_id, req.device_id, req.community_id, req.type, keyset.private_key
    )
    
    return SignTokenResponse(token=token, expires_at=expires_at)

@app.get("/my_logs")
def get_my_logs(x_device_id: str = Header(...), limit: int = 50, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.device_id == x_device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    events = db.query(Event).filter(
        Event.user_id == device.user_id,
        Event.verified == True
    ).order_by(Event.timestamp.desc()).limit(limit).all()
    
    return [
        EventResponse(
            event_id=e.event_id,
            community_id=e.community_id,
            type=e.type,
            timestamp=e.timestamp,
            pi_id=e.pi_id
        )
        for e in events
    ]

# ADMIN ENDPOINTS

@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    if req.username == ADMIN_USERNAME and req.password == ADMIN_PASSWORD:
        token = generate_admin_token(req.username)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/admin/requests")
def get_pending_requests(
    community_id: Optional[str] = None,
    admin: str = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    query = db.query(Membership).filter(Membership.status == "pending")
    if community_id:
        query = query.filter(Membership.community_id == community_id)
    
    requests = query.all()
    return [
        MembershipResponse(
            membership_id=r.membership_id,
            user_id=r.user_id,
            community_id=r.community_id,
            status=r.status,
            updated_at=r.updated_at
        )
        for r in requests
    ]

@app.post("/admin/approve")
def approve_membership(
    req: ApproveRequest,
    admin: str = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    membership = db.query(Membership).filter(Membership.membership_id == req.membership_id).first()
    if not membership:
        raise HTTPException(status_code=404, detail="Membership not found")
    
    membership.status = "approved"
    membership.approved_by = req.admin_id
    membership.updated_at = datetime.utcnow()
    db.commit()
    
    return {"success": True, "message": "Membership approved"}

@app.post("/admin/reject")
def reject_membership(
    req: ApproveRequest,
    admin: str = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    membership = db.query(Membership).filter(Membership.membership_id == req.membership_id).first()
    if not membership:
        raise HTTPException(status_code=404, detail="Membership not found")
    
    membership.status = "rejected"
    membership.approved_by = req.admin_id
    membership.updated_at = datetime.utcnow()
    db.commit()
    
    return {"success": True, "message": "Membership rejected"}

@app.get("/admin/logs")
def get_admin_logs(
    community_id: Optional[str] = None,
    user_id: Optional[str] = None,
    limit: int = 100,
    admin: str = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    query = db.query(Event)
    if community_id:
        query = query.filter(Event.community_id == community_id)
    if user_id:
        query = query.filter(Event.user_id == user_id)
    
    events = query.order_by(Event.timestamp.desc()).limit(limit).all()
    return events

@app.post("/admin/communities")
def create_community(
    req: CreateCommunityRequest,
    admin: str = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    existing = db.query(Community).filter(Community.community_id == req.community_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Community already exists")
    
    community = Community(
        community_id=req.community_id,
        name=req.name,
        description=req.description
    )
    db.add(community)
    
    # Generate Ed25519 keypair
    signing_key = SigningKey.generate()
    private_key_b64 = signing_key.encode(encoder=Base64Encoder).decode()
    public_key_b64 = signing_key.verify_key.encode(encoder=Base64Encoder).decode()
    
    keyset = Keyset(
        community_id=req.community_id,
        algo="ED25519",
        public_key=public_key_b64,
        private_key=private_key_b64,
        active=True
    )
    db.add(keyset)
    db.commit()
    
    return {"success": True, "community_id": req.community_id, "public_key": public_key_b64}

# PI ENDPOINTS

@app.get("/pi/config")
def get_pi_config(pi_id: str, db: Session = Depends(get_db)):
    communities = db.query(Community).all()
    keysets = db.query(Keyset).filter(Keyset.active == True).all()
    
    return PiConfigResponse(
        pi_id=pi_id,
        communities=[
            {"community_id": c.community_id, "name": c.name}
            for c in communities
        ],
        keysets=[
            {
                "community_id": k.community_id,
                "algo": k.algo,
                "public_key": k.public_key
            }
            for k in keysets
        ]
    )

@app.post("/pi/events")
def log_pi_events(pi_id: str, events: List[PiEventRequest], db: Session = Depends(get_db)):
    for evt in events:
        event = Event(
            user_id=evt.user_id,
            device_id=evt.device_id,
            community_id=evt.community_id,
            type=evt.type,
            pi_id=pi_id,
            timestamp=evt.timestamp,
            verified=evt.verified
        )
        db.add(event)
    db.commit()
    return {"success": True, "logged": len(events)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)