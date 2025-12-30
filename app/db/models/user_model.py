from typing import Optional, Literal
from pydantic import BaseModel, EmailStr
from datetime import datetime


class User(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    cnic: str
    password: str  # hashed password
    role: Literal["user", "admin"] = "user"  # Role-based access control
    # stored in db.users
    two_factor_enabled: bool = False
    # Add to user document when creating/updating
    is_blocked: bool = False
    blocked_until: Optional[datetime] = None
    blocked_reason: Optional[str] = None
    created_at: Optional[datetime] = None
    status: str = "active"