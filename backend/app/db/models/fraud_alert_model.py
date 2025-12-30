# app/db/models/fraud_alert_model.py
"""
FraudAlert Model for detected fraud incidents.

Alerts are derived from anomaly detection and can be managed by admins.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class AlertStatus(str, Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    MONITORING = "monitoring"
    RESOLVED = "resolved"


class AlertCategory(str, Enum):
    LOGIN = "login"
    TRANSACTION = "transaction"
    ACCOUNT = "account"
    SYSTEM = "system"


class FraudAlert(BaseModel):
    """Fraud alert model for MongoDB storage"""

    title: str
    description: str
    severity: AlertSeverity = AlertSeverity.WARNING
    category: AlertCategory
    status: AlertStatus = AlertStatus.ACTIVE
    priority_score: float = Field(ge=0, le=100, default=50.0)

    # Affected entities
    affected_user_ids: List[str] = Field(default_factory=list)
    affected_transaction_ids: List[str] = Field(default_factory=list)

    # Source information
    source_ip: Optional[str] = None
    source_location: Optional[Dict[str, Any]] = None

    # Detection details
    detection_method: Optional[str] = None  # "ml", "rule", "hybrid", "manual"
    detection_score: Optional[float] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)

    # Timeline
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None

    # Assignment
    assigned_to: Optional[str] = None  # admin_id
    notes: List[Dict[str, Any]] = Field(default_factory=list)

    # Related alerts (for fraud ring detection)
    related_alert_ids: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True
        json_schema_extra = {
            "example": {
                "title": "Multiple failed login attempts detected",
                "description": "User account shows 15 failed login attempts from different IPs in last hour",
                "severity": "warning",
                "category": "login",
                "status": "active",
                "priority_score": 75.0,
                "affected_user_ids": ["507f1f77bcf86cd799439011"],
                "source_ip": "192.168.1.100",
                "detection_method": "rule",
                "created_at": "2024-01-01T12:00:00Z",
            }
        }


class FraudAlertInDB(FraudAlert):
    """Fraud alert model with MongoDB _id"""

    id: Optional[str] = Field(None, alias="_id")

    class Config:
        populate_by_name = True
