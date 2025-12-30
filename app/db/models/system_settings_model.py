# app/db/models/system_settings_model.py
"""
SystemSettings Model for application configuration.

Single document in MongoDB to store all system settings.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class SecuritySettings(BaseModel):
    """Security-related settings"""

    auto_block_enabled: bool = True
    auto_block_threshold: int = Field(ge=0, le=100, default=85)
    max_login_attempts: int = Field(ge=1, le=20, default=5)
    session_timeout_minutes: int = Field(ge=5, le=1440, default=30)
    require_2fa_for_high_risk: bool = True
    lockout_duration_minutes: int = Field(ge=1, le=1440, default=30)


class DetectionSettings(BaseModel):
    """Fraud detection settings"""

    risk_threshold_flag: int = Field(ge=0, le=100, default=50)
    risk_threshold_block: int = Field(ge=0, le=100, default=85)
    ml_model_version: str = "v2.3.1"
    real_time_monitoring: bool = True
    rule_weight: float = Field(ge=0, le=1, default=0.4)
    ml_weight: float = Field(ge=0, le=1, default=0.6)


class NotificationSettings(BaseModel):
    """Notification settings"""

    email_alerts_enabled: bool = True
    sms_alerts_enabled: bool = False
    alert_email_recipients: List[str] = Field(default_factory=list)
    critical_alert_phone: Optional[str] = None
    alert_cooldown_minutes: int = Field(ge=1, le=60, default=5)


class SystemSettings(BaseModel):
    """Complete system settings model"""

    security: SecuritySettings = Field(default_factory=SecuritySettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    notifications: NotificationSettings = Field(default_factory=NotificationSettings)

    # Metadata
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    updated_by: Optional[str] = None  # admin_id

    class Config:
        json_schema_extra = {
            "example": {
                "security": {
                    "auto_block_enabled": True,
                    "auto_block_threshold": 85,
                    "max_login_attempts": 5,
                    "session_timeout_minutes": 30,
                    "require_2fa_for_high_risk": True,
                    "lockout_duration_minutes": 30,
                },
                "detection": {
                    "risk_threshold_flag": 50,
                    "risk_threshold_block": 85,
                    "ml_model_version": "v2.3.1",
                    "real_time_monitoring": True,
                    "rule_weight": 0.4,
                    "ml_weight": 0.6,
                },
                "notifications": {
                    "email_alerts_enabled": True,
                    "sms_alerts_enabled": False,
                    "alert_email_recipients": ["admin@linklock.com"],
                    "critical_alert_phone": None,
                    "alert_cooldown_minutes": 5,
                },
            }
        }


class SystemSettingsInDB(SystemSettings):
    """System settings model with MongoDB _id"""

    id: Optional[str] = Field(None, alias="_id")

    class Config:
        populate_by_name = True
