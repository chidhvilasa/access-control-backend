"""
Database Models for Access Control System
"""

from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, Literal
import os

Base = declarative_base()

# SQLAlchemy Models (Database)

class User(Base):
    __tablename__ = "users"
    user_id = Column(String(32), primary_key=True)
    phone = Column(String(20), unique=True, nullable=False)
    status = Column(String(20), default="active")
    created_at = Column(DateTime, default=datetime.utcnow)

class Device(Base):
    __tablename__ = "devices"
    device_id = Column(String(64), primary_key=True)
    user_id = Column(String(32), nullable=False)
    platform = Column(String(20))
    registered_at = Column(DateTime, default=datetime.utcnow)

class Community(Base):
    __tablename__ = "communities"
    community_id = Column(String(32), primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)

class Membership(Base):
    __tablename__ = "memberships"
    membership_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(32), nullable=False)
    community_id = Column(String(32), nullable=False)
    status = Column(String(20), default="pending")
    approved_by = Column(String(32))
    updated_at = Column(DateTime, default=datetime.utcnow)

class Event(Base):
    __tablename__ = "events"
    event_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(32), nullable=False)
    device_id = Column(String(64), nullable=False)
    community_id = Column(String(32), nullable=False)
    type = Column(String(10), nullable=False)
    pi_id = Column(String(32))
    timestamp = Column(DateTime, default=datetime.utcnow)
    verified = Column(Boolean, default=True)

class Keyset(Base):
    __tablename__ = "keysets"
    keyset_id = Column(Integer, primary_key=True, autoincrement=True)
    community_id = Column(String(32), nullable=False)
    algo = Column(String(20), default="ED25519")
    public_key = Column(Text, nullable=False)
    private_key = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    active = Column(Boolean, default=True)

class NonceSeen(Base):
    __tablename__ = "nonces_seen"
    nonce_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(32))
    community_id = Column(String(32))
    nonce = Column(String(32), unique=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

# Pydantic Models (API Request/Response)

class RegisterDeviceRequest(BaseModel):
    device_id: str
    user_id: str
    phone: str
    platform: str = "android"
    community_id: str

class SignTokenRequest(BaseModel):
    user_id: str
    device_id: str
    community_id: str
    type: Literal["entry", "exit"]

class SignTokenResponse(BaseModel):
    token: str
    expires_at: int

class CommunityResponse(BaseModel):
    community_id: str
    name: str
    description: Optional[str]
    status: str

class EventResponse(BaseModel):
    event_id: int
    community_id: str
    type: str
    timestamp: datetime
    pi_id: Optional[str]

class AdminLoginRequest(BaseModel):
    username: str
    password: str

class ApproveRequest(BaseModel):
    membership_id: int
    admin_id: str

class MembershipResponse(BaseModel):
    membership_id: int
    user_id: str
    community_id: str
    status: str
    updated_at: datetime

class PiConfigResponse(BaseModel):
    pi_id: str
    communities: list
    keysets: list

class PiEventRequest(BaseModel):
    user_id: str
    device_id: str
    community_id: str
    type: str
    timestamp: datetime
    verified: bool = True

class CreateCommunityRequest(BaseModel):
    community_id: str
    name: str
    description: Optional[str] = None