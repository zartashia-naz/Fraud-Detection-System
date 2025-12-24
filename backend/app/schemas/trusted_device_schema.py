# ============================================================================
# FILE 2: backend/app/schemas/trusted_device_schema.py
# ============================================================================

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any


class TrustDeviceRequest(BaseModel):
    """
    Request schema for trusting a device.
    """
    login_log_id: str = Field(..., description="ID of the login log entry to trust")
    

class TrustedDeviceResponse(BaseModel):
    """
    Response schema for trusted device.
    """
    id: str = Field(..., alias="_id", description="Trusted device ID")
    user_id: str
    device_id: str
    device_name: str
    device_info: Dict[str, Any]
    trusted_at: datetime
    first_used: datetime
    last_used: datetime
    ip_address: str
    location: Dict[str, Any]
    is_active: bool
    
    class Config:
        populate_by_name = True


class TrustedDevicesListResponse(BaseModel):
    """
    Response schema for list of trusted devices.
    """
    devices: list[TrustedDeviceResponse]
    total: int


class RevokeDeviceRequest(BaseModel):
    """
    Request schema for revoking a trusted device.
    """
    device_id: str = Field(..., description="Device ID to revoke")
