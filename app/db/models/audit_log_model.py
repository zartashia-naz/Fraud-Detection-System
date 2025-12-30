# app/db/models/audit_log_model.py
"""
AuditLog Model for tracking all admin actions.

Provides complete audit trail for compliance and security.
"""

from datetime import datetime
from typing import Optional, Any, Dict
from pydantic import BaseModel, Field


class AuditLog(BaseModel):
    """Audit log model for MongoDB storage"""

    admin_id: str
    admin_email: str
    action: str  # e.g., "user_blocked", "transaction_approved", "settings_changed"
    target_type: Optional[str] = None  # e.g., "user", "transaction", "alert", "settings"
    target_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_schema_extra = {
            "example": {
                "admin_id": "507f1f77bcf86cd799439011",
                "admin_email": "admin@linklock.com",
                "action": "user_blocked",
                "target_type": "user",
                "target_id": "507f1f77bcf86cd799439022",
                "details": {"reason": "Suspicious activity", "duration_hours": 24},
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "created_at": "2024-01-01T12:00:00Z",
            }
        }


class AuditLogInDB(AuditLog):
    """Audit log model with MongoDB _id"""

    id: Optional[str] = Field(None, alias="_id")

    class Config:
        populate_by_name = True
