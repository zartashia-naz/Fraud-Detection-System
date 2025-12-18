# from pydantic import BaseModel, EmailStr, Field

# class UserSignup(BaseModel):
#     first_name: str = Field(..., alias="firstName")
#     last_name: str = Field(..., alias="lastName")
#     email: EmailStr
#     phone: str
#     cnic: str
#     password: str

#     class Config:
#         populate_by_name = True

# class UserLogin(BaseModel):
#     email: EmailStr
#     password: str

# class UserResponse(BaseModel):
#     id: str
#     email: EmailStr
#     first_name: str
#     last_name: str
#     phone: str
#     cnic: str

# class TokenResponse(BaseModel):
#     access_token: str
#     token_type: str = "bearer"




# ===========CLAUDE CODE BELOW===============

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


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    requires_2fa: bool = False  # 🔥 NEW: For future 2FA
    risk_score: Optional[int] = None  # 🔥 NEW: For monitoring