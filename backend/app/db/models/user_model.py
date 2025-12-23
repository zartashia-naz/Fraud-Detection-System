from typing import Optional
from pydantic import BaseModel, EmailStr

class User(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    cnic: str
    password: str  # hashed password
    # stored in db.users
    two_factor_enabled: False
    # Add to user document when creating/updating
    is_blocked: False
    blocked_until: None
    blocked_reason: None