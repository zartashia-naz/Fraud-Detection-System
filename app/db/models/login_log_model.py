# backend/app/db/models/login_logs_model.py

from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class LoginLogModel(BaseModel):
    """
    Model for login log entries.

    Now also stores hybrid anomaly detection results from the
    rule-based engine and Isolation Forest model.
    """

    # Core identity / context
    user_id: Optional[str] = None  # None for failed attempts where user doesn't exist
    email: str
    device_id: str
    device_name: Optional[str] = None
    device_info: Optional[Dict[str, Any]] = None  # Full device fingerprint data
    ip_address: str

    # Timing / history
    login_time: datetime = Field(default_factory=datetime.utcnow)
    previous_login_time: Optional[datetime] = None
    login_attempts: int = 1

    # Location
    location: Optional[Dict[str, Any]] = None

    # Status
    status: str = "success"  # success, failed, blocked

    # Hybrid detection outputs
    # Raw flags / scores from hybrid_login_decision
    rule_flag: Optional[int] = None                 # 0/1 rule-based decision
    rule_score: Optional[float] = None              # 0.0–1.0 rule-based weight
    ml_score: Optional[float] = None                # 0.0–1.0 ML anomaly score
    hybrid_score: Optional[float] = None            # 0.0–1.0 combined score
    is_moderate: Optional[int] = None               # 0/1 moderate suspicion flag
    is_anomaly: bool = False                        # final anomaly flag (from hybrid)
    anomaly_reason: Optional[str] = None  # Human-readable reason
    
    # Legacy / phase-2 risk fields (kept for compatibility)
    risk_score: int = 0                             # 0–100 risk score (optional mapping)
    rule_based_score: Optional[int] = None          # legacy rule score (0–100)
    rule_reasons: Optional[Dict[str, Any]] = None   # reasons / context for rules

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "user_id": "6932f0839e3c414dc16273a0",
                "email": "user@example.com",
                "device_id": "device-a1b2c3d4e5f6g7h8",
                "device_name": "Chrome on Windows",
                "device_info": {
                    "browser": {"name": "Chrome", "version": "120.0.0"},
                    "os": {"name": "Windows", "version": "10"},
                },
                "ip_address": "192.168.1.1",
                "login_time": "2025-12-13T10:30:00",
                "previous_login_time": "2025-12-12T09:15:00",
                "login_attempts": 5,
                "location": {
                    "country": "Pakistan",
                    "city": "Lahore",
                    "latitude": 31.5204,
                    "longitude": 74.3587,
                },
                "status": "success",
                "rule_flag": 0,
                "rule_score": 0.0,
                "ml_score": 0.15,
                "hybrid_score": 0.09,
                "is_moderate": 0,
                "is_anomaly": False,
                "risk_score": 15,
            }
        }