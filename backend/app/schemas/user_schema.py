# backend/app/schemas/user_schema.py

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, Any

class UserSignup(BaseModel):
    first_name: str = Field(..., alias="firstName")
    last_name: str = Field(..., alias="lastName")
    email: EmailStr
    phone: str
    cnic: str
    password: str

    class Config:
        populate_by_name = True


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    device_data: Optional[Dict[str, Any]] = None  # 🔥 NEW: Device fingerprint data


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    first_name: str
    last_name: str
    phone: str
    cnic: str
    two_factor_enabled: bool = False  # 🔥 NEW: 2FA status

class TokenResponse(BaseModel):
    # access_token: str
    access_token: Optional[str] = None
    token_type: str = "bearer"
    role: str = Field("user", description="User role: 'user' or 'admin'")  # Role for frontend routing
    requires_2fa: bool = False  # 🔥 NEW: For future 2FA
    risk_score: Optional[int] = None  # 🔥 NEW: For monitoring
    # ✅ ADD THESE NEW FIELDS
    is_moderate_risk: bool = Field(False, description="Show 'trust device' option")
    is_high_risk: bool = Field(False, description="High risk - require 2FA/block")
    is_trusted_device: bool = Field(False, description="Login from trusted device")
    requires_device_trust: bool = Field(False, description="New device - ask user to trust it")  # ✅ NEW
    login_log_id: Optional[str] = Field(None, description="Login log ID for trust action")
    anomaly_reason: Optional[str] = Field(None, description="Reason for anomaly")
    # Admin-specific fields (only populated for admin login)
    user: Optional[dict] = Field(None, description="User/Admin profile info")