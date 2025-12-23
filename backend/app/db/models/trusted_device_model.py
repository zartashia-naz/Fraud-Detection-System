# ============================================================================
# FILE 1: backend/app/db/models/trusted_device_model.py
# ============================================================================

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class TrustedDeviceModel(BaseModel):
    """
    Model for trusted devices collection.
    Stores devices that users have explicitly marked as trusted.
    """
    user_id: str
    device_id: str
    device_name: str
    device_info: dict
    
    # Trust metadata
    trusted_at: datetime = Field(default_factory=datetime.utcnow)
    first_used: datetime = Field(default_factory=datetime.utcnow)
    last_used: datetime = Field(default_factory=datetime.utcnow)
    
    # Security tracking
    ip_address: str  # IP when device was trusted
    location: dict   # Location when device was trusted
    
    # Status
    is_active: bool = True
    revoked_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True