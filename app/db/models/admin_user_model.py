# app/db/models/admin_user_model.py
"""
AdminUser Model for LinkLock Admin Panel.

Admin accounts are stored separately from regular users.
Single admin type with full dashboard access.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class AdminUser(BaseModel):
    """Admin user model for MongoDB storage"""

    email: EmailStr
    password_hash: str
    first_name: str
    last_name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    is_active: bool = True

    class Config:
        json_schema_extra = {
            "example": {
                "email": "admin@linklock.com",
                "password_hash": "$2b$12$...",
                "first_name": "Admin",
                "last_name": "User",
                "created_at": "2024-01-01T00:00:00Z",
                "last_login": None,
                "is_active": True,
            }
        }


class AdminUserInDB(AdminUser):
    """Admin user model with MongoDB _id"""

    id: Optional[str] = Field(None, alias="_id")

    class Config:
        populate_by_name = True
