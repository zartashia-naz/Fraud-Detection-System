# from pydantic import BaseModel
# from datetime import datetime
# from typing import Optional, Dict

# class LoginLogCreate(BaseModel):
#     device_id: Optional[str] = None
#     login_status: str = "success"


# class LoginLogResponse(BaseModel):
#     id: str
#     user_id: str
#     email: Optional[str] = None
#     device_id: str
#     ip_address: str
#     location: Dict
#     login_time: datetime
#     previous_login_time: Optional[datetime] = None
#     login_attempts: int
#     is_anomaly: bool = False

# ==================CLAUDE CODE BELOW===============


# backend/app/schemas/login_log_schema.py

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any


class LoginLogCreate(BaseModel):
    """
    Schema for creating a login log entry.

    Note: Hybrid detection fields are populated server-side and are
    therefore not part of the create payload.
    """

    user_id: Optional[str]
    email: str
    device_id: str
    device_name: Optional[str] = None
    device_info: Optional[Dict[str, Any]] = None
    ip_address: str
    location: Dict[str, Any]
    login_time: datetime = Field(default_factory=datetime.utcnow)
    previous_login_time: Optional[datetime] = None
    login_attempts: int = 1
    status: str = "success"


class LoginLogResponse(BaseModel):
    """
    Response model for login log entries.

    Includes hybrid anomaly detection results from the rule-based
    engine and ML model.
    """

    id: str = Field(..., description="Login log ID")
    user_id: Optional[str] = Field(None, description="User ID (null for failed attempts)")
    email: str = Field(..., description="User email")
    device_id: str = Field(..., description="Unique device identifier")
    device_name: Optional[str] = Field(None, description="Human-readable device name")
    device_info: Optional[Dict[str, Any]] = Field(None, description="Detailed device information")
    ip_address: str = Field(..., description="IP address of login attempt")
    location: Dict[str, Any] = Field(..., description="Geolocation data")
    login_time: datetime = Field(..., description="Timestamp of login attempt")
    previous_login_time: Optional[datetime] = Field(None, description="Previous successful login time")
    login_attempts: int = Field(..., description="Total login count for this user")
    status: str = Field(..., description="Login status: success, failed, or blocked")

    # Hybrid anomaly detection fields
    rule_flag: Optional[int] = Field(None, description="Rule-based anomaly decision flag (0/1)")
    rule_score: Optional[float] = Field(None, description="Rule-based anomaly score (0.0–1.0)")
    ml_score: Optional[float] = Field(None, description="ML anomaly score from Isolation Forest (0.0–1.0)")
    hybrid_score: Optional[float] = Field(None, description="Combined hybrid anomaly score (0.0–1.0)")
    is_moderate: Optional[int] = Field(None, description="Moderate suspicion flag (0/1)")
    is_anomaly: bool = Field(False, description="Final anomaly decision flag from hybrid detector")

    # Optional risk abstractions (kept for compatibility / UI)
    risk_score: int = Field(0, description="Calculated risk score (0-100), e.g. scaled from hybrid_score")
    rule_based_score: Optional[int] = Field(None, description="Legacy rule-based detection score (0-100)")
    rule_reasons: Optional[Dict[str, Any]] = Field(None, description="Reasons for rule-based flags")

    class Config:
        from_attributes = True


class LoginStatsResponse(BaseModel):
    """
    Response model for login statistics
    """
    total_logins: int
    failed_attempts_30d: int
    unique_devices: int
    unique_locations: int
    last_login: Optional[Dict[str, Any]]


class DeviceResponse(BaseModel):
    """
    Response model for device information
    """
    device_id: str = Field(..., alias="_id")
    device_name: str
    device_info: Dict[str, Any]
    last_used: datetime
    first_used: datetime
    login_count: int
    locations: list[str]
    
    class Config:
        populate_by_name = True


class SuspiciousActivityResponse(BaseModel):
    """
    Response model for suspicious activity
    """
    suspicious_logins: list[LoginLogResponse]
    count: int


class LoginLogsListResponse(BaseModel):
    """
    Response model for paginated login logs list
    """
    logs: list[LoginLogResponse]
    total: int
    limit: int
    skip: int