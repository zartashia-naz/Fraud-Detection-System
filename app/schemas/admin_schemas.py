# app/schemas/admin_schemas.py
"""
Admin Panel Schemas for Request/Response validation.

Contains all Pydantic schemas for admin API endpoints.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field
from enum import Enum


# ========================================
# AUTHENTICATION SCHEMAS
# ========================================

class AdminLogin(BaseModel):
    """Admin login request"""
    email: EmailStr
    password: str


class AdminTokenResponse(BaseModel):
    """Admin login response"""
    access_token: str
    token_type: str = "bearer"
    role: str = "admin"
    admin: dict


class AdminProfile(BaseModel):
    """Admin profile response"""
    id: str
    email: EmailStr
    first_name: str
    last_name: str
    role: str = "admin"
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True



# ========================================
# DASHBOARD SCHEMAS
# ========================================

class DashboardStats(BaseModel):
    """Dashboard statistics response"""
    total_users: int
    transactions_today: int
    fraud_detected_today: int
    system_security_score: float
    active_users_now: int
    pending_alerts: int


class KPIItem(BaseModel):
    """Single KPI with change indicator (KEEP FOR OTHER ENDPOINTS)"""
    value: float
    change: float  # Percentage change from previous period
    trend: str  # "up", "down", "stable"
    previous_value: float = 0


class EnhancedStatsResponse(BaseModel):
    """Enhanced dashboard statistics with 4 KPIs (KEEP FOR OTHER ENDPOINTS)"""
    total_users: KPIItem
    volume_today: KPIItem  # Transaction volume
    fraud_today: KPIItem  # Detected fraud count
    fraud_prevented: KPIItem  # Blocked transactions value


# 🔥 NEW: FLAT EnhancedDashboardStats - EXACTLY matches frontend.tsx expectations
class EnhancedDashboardStats(BaseModel):
    """FLAT numeric values for React frontend dashboard.tsx - FIXES [object Object]"""
    total_users: int = 0
    users_change_wow: float = 0.0  # Week-over-week % change

    total_transaction_volume_today: float = 0.0
    volume_change_wow: float = 0.0  # Day-over-day % change

    fraud_detected_today: int = 0
    fraud_change_wow: float = 0.0  # Day-over-day % change

    fraud_prevented_value: float = 0.0
    blocked_transactions_today: int = 0

    # Optional enhanced fields (frontend fallback uses these)
    model_accuracy: float = 0.0
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    avg_response_time_ms: int = 0
    high_risk_users: int = 0
    critical_alerts_pending: int = 0

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class FraudTrendItem(BaseModel):
    """Single fraud trend data point"""
    date: str
    detected_count: int
    blocked_count: int
    false_positives: int = 0


class FraudTrendsResponse(BaseModel):
    """Fraud trends response"""
    range: str
    data: List[FraudTrendItem]


class ThreatDistributionItem(BaseModel):
    """Single threat type data"""
    type: str
    count: int
    percentage: float


class ThreatDistributionResponse(BaseModel):
    """Threat distribution response"""
    data: List[ThreatDistributionItem]


class RecentAlertItem(BaseModel):
    """Recent alert item"""
    id: str
    type: str
    title: str
    severity: str
    timestamp: datetime
    status: str


class ActiveUserItem(BaseModel):
    """Active user item"""
    id: str
    name: str
    email: str
    risk_score: int
    last_activity: datetime


# ========================================
# NEW VISUALIZATION SCHEMAS (for other dashboard charts)
# ========================================

class RiskScoreTrendItem(BaseModel):
    """Fraud risk score trend for line chart"""
    date: str
    avg_risk_score: float
    max_risk_score: float
    high_risk_count: int


class RiskScoreTrendsResponse(BaseModel):
    """Risk score trends response"""
    data: List[RiskScoreTrendItem]


class TransactionStatusItem(BaseModel):
    """Transaction status breakdown for pie chart"""
    status: str
    count: int
    percentage: float


class TransactionStatusBreakdownResponse(BaseModel):
    """Transaction status breakdown response"""
    data: List[TransactionStatusItem]


class SuspiciousLoginLocationItem(BaseModel):
    """Suspicious login location for map view"""
    city: str
    country_name: str
    suspicious_login_count: int
    blocked_count: int
    risk_level: str


class SuspiciousLoginLocationsResponse(BaseModel):
    """Suspicious locations response"""
    data: List[SuspiciousLoginLocationItem]


class TopFailedLoginUserItem(BaseModel):
    """Top failed login user for bar chart"""
    user_name: str
    user_email: str
    failed_login_count: int
    risk_score: float
    is_blocked: bool


class TopFailedLoginsResponse(BaseModel):
    """Top failed logins response"""
    data: List[TopFailedLoginUserItem]


class FraudHeatmapItem(BaseModel):
    """Fraud heatmap data point"""
    day: str
    hour: int
    intensity: float  # 0.0 to 1.0


class FraudHeatmapResponse(BaseModel):
    """Fraud heatmap response"""
    data: List[FraudHeatmapItem]


class ClusterAccountItem(BaseModel):
    """Account in a suspicious cluster"""
    user_name: str
    risk_score: float


class DeviceIPClusterItem(BaseModel):
    """Device/IP cluster for network diagram"""
    cluster_id: str
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    total_accounts: int
    is_suspicious: bool
    accounts: List[ClusterAccountItem]


class DeviceIPClustersResponse(BaseModel):
    """Device/IP clusters response"""
    data: List[DeviceIPClusterItem]


class OTPFunnelStageItem(BaseModel):
    """OTP funnel stage"""
    stage: str  # "sent", "delivered", "verified"
    count: int
    percentage: float


class OTPFunnelResponse(BaseModel):
    """OTP funnel response"""
    data: List[OTPFunnelStageItem]


class FraudClassificationItem(BaseModel):
    """Fraud classification for pie chart"""
    classification: str  # "normal", "flagged", "blocked"
    count: int
    percentage: float
    trend: str  # "up", "down", "stable"
    change_percentage: float


class FraudClassificationResponse(BaseModel):
    """Fraud classification response"""
    data: List[FraudClassificationItem]

# ========================================
# USER MANAGEMENT SCHEMAS
# ========================================

class UserListItem(BaseModel):
    """User list item for admin view"""
    id: str
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    cnic: str
    status: str
    risk_score: int = 0
    transaction_count: int = 0
    total_transaction_volume: float = 0
    created_at: datetime
    last_login: Optional[datetime] = None
    last_active: Optional[datetime] = None
    two_factor_enabled: bool = False


class UserListResponse(BaseModel):
    """Paginated user list response"""
    users: List[UserListItem]
    total: int
    page: int
    limit: int
    pages: int


class UserDetailResponse(BaseModel):
    """Detailed user profile for admin"""
    id: str
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    cnic: str
    status: str
    risk_score: int = 0
    transaction_count: int = 0
    total_transaction_volume: float = 0
    created_at: datetime
    last_login: Optional[datetime] = None
    last_active: Optional[datetime] = None
    two_factor_enabled: bool = False
    is_blocked: bool = False
    blocked_until: Optional[datetime] = None
    blocked_reason: Optional[str] = None
    account_balance: float = 0
    trusted_devices: List[dict] = []
    recent_transactions: List[dict] = []
    login_history: List[dict] = []
    fraud_alerts: List[dict] = []
    risk_factors: Dict[str, Any] = {}


class UserUpdateRequest(BaseModel):
    """Update user request"""
    status: Optional[str] = None
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    notes: Optional[str] = None


class UserBlockRequest(BaseModel):
    """Block user request"""
    reason: str
    duration_hours: Optional[int] = None  # None = permanent


class UserStatsResponse(BaseModel):
    """User statistics response"""
    total_users: int
    active_count: int
    flagged_count: int
    suspended_count: int
    pending_count: int
    new_users_today: int
    new_users_this_week: int


# ========================================
# TRANSACTION MANAGEMENT SCHEMAS
# ========================================

class TransactionListItem(BaseModel):
    """Transaction list item for admin view"""
    id: str
    user_id: str
    user_name: str
    user_email: str
    type: str  # credit/debit
    amount: float
    currency: str = "PKR"
    description: str
    status: str
    risk_level: str
    risk_score: int
    fraud_indicators: List[str] = []
    created_at: datetime
    ip_address: Optional[str] = None
    device_id: Optional[str] = None
    location: Optional[dict] = None


class TransactionListResponse(BaseModel):
    """Paginated transaction list response"""
    transactions: List[TransactionListItem]
    total: int
    page: int
    limit: int
    pages: int


class TransactionDetailResponse(BaseModel):
    """Detailed transaction for admin"""
    id: str
    user_id: str
    user_name: str
    user_email: str
    amount: float
    category: str
    description: str
    status: str
    risk_score: int
    risk_level: str

    # ML Analysis
    ml_analysis: Dict[str, Any] = {}
    risk_factors: List[Dict[str, Any]] = []

    # Transaction metadata
    ip_address: Optional[str] = None
    device_id: Optional[str] = None
    location: Optional[dict] = None
    created_at: datetime
    processed_at: Optional[datetime] = None

    # Related data
    similar_transactions: List[dict] = []
    user_transaction_summary: Dict[str, Any] = {}


class TransactionActionRequest(BaseModel):
    """Request for transaction actions (approve/reject/flag)"""
    admin_notes: Optional[str] = None
    reason: Optional[str] = None
    block_user: bool = False
    risk_level: Optional[str] = None


class TransactionStatsResponse(BaseModel):
    """Transaction statistics response"""
    total_count: int
    total_volume: float
    average_amount: float
    flagged_count: int
    blocked_count: int
    at_risk_volume: float
    by_status: Dict[str, int]
    by_risk_level: Dict[str, int]


# ========================================
# ALERT MANAGEMENT SCHEMAS
# ========================================

class AlertListItem(BaseModel):
    """Alert list item"""
    id: str
    type: str  # severity
    category: str
    title: str
    description: str
    status: str
    priority_score: float
    affected_users_count: int
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None


class AlertListResponse(BaseModel):
    """Paginated alert list response"""
    alerts: List[AlertListItem]
    total: int
    page: int
    limit: int
    pages: int


class AlertDetailResponse(BaseModel):
    """Detailed alert for admin"""
    id: str
    title: str
    description: str
    severity: str
    category: str
    status: str
    priority_score: float
    affected_user_ids: List[str] = []
    affected_transaction_ids: List[str] = []
    source_ip: Optional[str] = None
    source_location: Optional[dict] = None
    detection_method: Optional[str] = None
    detection_score: Optional[float] = None
    evidence: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    notes: List[Dict[str, Any]] = []
    timeline: List[Dict[str, Any]] = []
    related_alerts: List[dict] = []
    recommended_actions: List[str] = []


class AlertStatusUpdateRequest(BaseModel):
    """Update alert status request"""
    status: str  # investigating, monitoring, resolved
    notes: Optional[str] = None


class AlertEscalateRequest(BaseModel):
    """Escalate alert request"""
    reason: str
    priority: Optional[int] = None


class AlertStatsResponse(BaseModel):
    """Alert statistics response"""
    total_active: int
    critical_count: int
    warning_count: int
    info_count: int
    by_category: Dict[str, int]
    avg_resolution_time_hours: float
    resolved_today: int
    new_today: int


# ========================================
# ENHANCED FRAUD ALERTS SCHEMAS
# ========================================

class FraudAlertUserInfo(BaseModel):
    """User information for fraud alert"""
    id: str
    email: str
    first_name: str
    last_name: str
    phone: Optional[str] = None
    status: str
    risk_score: int = 0
    total_alerts: int = 0
    is_blocked: bool = False


class FraudAlertItem(BaseModel):
    """Enhanced fraud alert with user details"""
    id: str
    alert_type: str  # "login_anomaly", "transaction_anomaly", "moderate_risk_login"
    severity: str  # "critical", "warning", "moderate"
    title: str
    reason: str  # Detailed reason for the alert
    risk_score: float
    status: str  # "pending", "investigating", "resolved"
    source: str  # "anomaly_logs", "login_logs"

    # User details
    user: Optional[FraudAlertUserInfo] = None

    # Event details
    event_data: Dict[str, Any] = {}  # IP, device, location, amount, etc.

    # Timestamps
    detected_at: datetime
    created_at: Optional[datetime] = None

    # Login specific
    login_status: Optional[str] = None  # "success", "failed"
    ip_address: Optional[str] = None
    device_info: Optional[Any] = None  # Can be string or dict
    location: Optional[Any] = None  # Can be string or dict

    # Transaction specific
    amount: Optional[float] = None
    transaction_type: Optional[str] = None


class FraudAlertListResponse(BaseModel):
    """Paginated fraud alert list response"""
    alerts: List[FraudAlertItem]
    total: int
    page: int
    limit: int
    pages: int

    # Summary stats
    by_type: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}


class FraudAlertUserSummary(BaseModel):
    """User with alert count summary"""
    user: FraudAlertUserInfo
    alert_count: int
    critical_count: int
    warning_count: int
    moderate_count: int
    last_alert_at: Optional[datetime] = None


class TopAlertUsersResponse(BaseModel):
    """Response for users with most alerts"""
    users: List[FraudAlertUserSummary]
    total: int


# ========================================
# FRAUD ALERTS KPI SCHEMAS
# ========================================

class FraudAlertsKPIResponse(BaseModel):
    """KPIs for fraud alerts page"""
    # Login KPIs
    login_flagged: int = 0  # Moderate risk logins (is_moderate=1)
    login_blocked: int = 0  # Blocked/high-risk logins (status=blocked or is_anomaly=True)

    # Transaction KPIs
    transaction_flagged: int = 0  # Flagged transactions (from flagged_transactions)
    transaction_blocked: int = 0  # Blocked transactions (from anomaly_logs with type=transaction)

    # Today's counts
    login_flagged_today: int = 0
    login_blocked_today: int = 0
    transaction_flagged_today: int = 0
    transaction_blocked_today: int = 0

    # Totals
    total_alerts: int = 0
    total_today: int = 0


class TopOffenderItem(BaseModel):
    """Top offender user details"""
    user_id: str
    email: str
    first_name: str
    last_name: str
    account_risk_score: int = 0
    is_blocked: bool = False
    status: str = "active"

    # Login stats
    login_flagged: int = 0
    login_blocked: int = 0

    # Transaction stats
    transaction_flagged: int = 0
    transaction_blocked: int = 0

    # Totals
    total_flagged: int = 0
    total_blocked: int = 0
    total_incidents: int = 0

    last_incident_at: Optional[datetime] = None


class TopOffendersResponse(BaseModel):
    """Response for top offenders list"""
    offenders: List[TopOffenderItem]
    total: int


# ========================================
# DASHBOARD VISUALIZATION SCHEMAS
# ========================================

# 1. Risk Score Trends (Line Chart)
class RiskScoreTrendItem(BaseModel):
    """Single data point for risk score trend"""
    date: str
    avg_risk_score: float
    max_risk_score: float
    min_risk_score: float
    high_risk_count: int
    total_transactions: int


class RiskScoreTrendsResponse(BaseModel):
    """Response for risk score trends"""
    data: List[RiskScoreTrendItem]


# 2. Transaction Status Breakdown (Donut Chart)
class TransactionStatusItem(BaseModel):
    """Transaction status breakdown item"""
    status: str
    count: int
    percentage: float
    volume: float


class TransactionStatusBreakdownResponse(BaseModel):
    """Response for transaction status breakdown"""
    data: List[TransactionStatusItem]


# 3. Suspicious Login Locations (Map View)
class SuspiciousLoginLocationItem(BaseModel):
    """Suspicious login location data"""
    country_code: str
    country_name: str
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    suspicious_login_count: int
    blocked_count: int
    risk_level: str  # critical, high, medium, low


class SuspiciousLoginLocationsResponse(BaseModel):
    """Response for suspicious login locations"""
    data: List[SuspiciousLoginLocationItem]


# 4. Top Failed Login Users (Bar Chart)
class TopFailedLoginUserItem(BaseModel):
    """User with failed login attempts"""
    user_id: str
    user_name: str
    user_email: str
    failed_login_count: int
    last_failed_attempt: Optional[datetime] = None
    is_blocked: bool = False
    risk_score: int = 0


class TopFailedLoginsResponse(BaseModel):
    """Response for top failed login users"""
    data: List[TopFailedLoginUserItem]


# 5. Fraud Heatmap (Hours x Days)
class FraudHeatmapItem(BaseModel):
    """Single cell in fraud heatmap"""
    day: int  # 0-6 (Sunday-Saturday)
    day_name: str
    hour: int  # 0-23
    fraud_count: int
    transaction_count: int
    fraud_rate: float
    intensity: float  # 0-1 normalized


class FraudHeatmapResponse(BaseModel):
    """Response for fraud heatmap"""
    data: List[FraudHeatmapItem]


# 6. Device/IP Clusters (Network View)
class ClusterAccountItem(BaseModel):
    """Account in a cluster"""
    user_id: str
    user_name: str
    user_email: str
    risk_score: int = 0


class DeviceIPClusterItem(BaseModel):
    """Device/IP cluster data"""
    cluster_id: str
    cluster_type: str  # "device" or "ip"
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    accounts: List[ClusterAccountItem]
    total_accounts: int
    is_suspicious: bool = False
    first_seen: Optional[datetime] = None
    last_activity: Optional[datetime] = None


class DeviceIPClustersResponse(BaseModel):
    """Response for device/IP clusters"""
    data: List[DeviceIPClusterItem]


# 7. OTP Funnel Data
class OTPFunnelStageItem(BaseModel):
    """OTP funnel stage data"""
    stage: str  # sent, delivered, verified
    count: int
    percentage: float
    drop_rate: float


class OTPFunnelResponse(BaseModel):
    """Response for OTP funnel"""
    data: List[OTPFunnelStageItem]


# 8. Device Trust Distribution (Pie Chart)
class DeviceTrustItem(BaseModel):
    """Device trust distribution item"""
    type: str  # trusted, untrusted, new
    count: int
    percentage: float
    login_count: int


class DeviceTrustResponse(BaseModel):
    """Response for device trust distribution"""
    data: List[DeviceTrustItem]


# 9. Fraud Classification Distribution (Pie Chart)
class FraudClassificationItem(BaseModel):
    """Fraud classification item"""
    classification: str  # normal, flagged, blocked
    count: int
    percentage: float
    trend: str  # up, down, stable
    change_percentage: float


class FraudClassificationResponse(BaseModel):
    """Response for fraud classification distribution"""
    data: List[FraudClassificationItem]


# ========================================
# ANALYTICS SCHEMAS
# ========================================

class HourlyActivityItem(BaseModel):
    """Hourly activity data point"""
    hour: int
    transaction_count: int
    fraud_count: int
    avg_risk_score: float


class GeographicDataItem(BaseModel):
    """Geographic data point"""
    country_code: str
    country_name: str
    transaction_count: int
    fraud_rate: float
    blocked_count: int


class FraudTypeItem(BaseModel):
    """Fraud type distribution item"""
    type: str
    count: int
    percentage: float
    trend: str  # up, down, stable


class AnalyticsMetrics(BaseModel):
    """Analytics KPIs"""
    detection_rate: float
    avg_response_time_seconds: float
    false_positive_rate: float
    user_reports_count: int
    model_accuracy: float
    blocked_fraud_value: float


class RiskDistributionItem(BaseModel):
    """Risk distribution bucket"""
    risk_bucket: str  # "0-20", "21-40", etc.
    user_count: int
    percentage: float


# ========================================
# SETTINGS SCHEMAS
# ========================================

class SecuritySettingsSchema(BaseModel):
    """Security settings schema"""
    auto_block_enabled: bool = True
    auto_block_threshold: int = 85
    max_login_attempts: int = 5
    session_timeout_minutes: int = 30
    require_2fa_for_high_risk: bool = True
    lockout_duration_minutes: int = 30


class DetectionSettingsSchema(BaseModel):
    """Detection settings schema"""
    risk_threshold_flag: int = 50
    risk_threshold_block: int = 85
    ml_model_version: str = "v2.3.1"
    real_time_monitoring: bool = True
    rule_weight: float = 0.4
    ml_weight: float = 0.6


class NotificationSettingsSchema(BaseModel):
    """Notification settings schema"""
    email_alerts_enabled: bool = True
    sms_alerts_enabled: bool = False
    alert_email_recipients: List[str] = []
    critical_alert_phone: Optional[str] = None
    alert_cooldown_minutes: int = 5


class SystemSettingsResponse(BaseModel):
    """Complete system settings response"""
    security: SecuritySettingsSchema
    detection: DetectionSettingsSchema
    notifications: NotificationSettingsSchema
    updated_at: Optional[datetime] = None
    updated_by: Optional[str] = None


class SystemSettingsUpdateRequest(BaseModel):
    """Update settings request (partial update)"""
    security: Optional[SecuritySettingsSchema] = None
    detection: Optional[DetectionSettingsSchema] = None
    notifications: Optional[NotificationSettingsSchema] = None


class SystemHealthResponse(BaseModel):
    """System health check response"""
    api_status: str  # operational, degraded, down
    database_status: str
    ml_service_status: str
    cache_status: str
    uptime_seconds: int
    last_incident: Optional[datetime] = None
    response_time_ms: float


# ========================================
# DETECTION RULE SCHEMAS
# ========================================

class DetectionRuleCreate(BaseModel):
    """Create detection rule request"""
    name: str
    description: str
    type: str = "rule"  # ml, rule, hybrid
    conditions: Dict[str, Any]
    threshold: float = Field(ge=0, le=100, default=50.0)
    action: str = "flag"  # flag, block, alert, log
    tags: List[str] = []


class DetectionRuleUpdate(BaseModel):
    """Update detection rule request"""
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    conditions: Optional[Dict[str, Any]] = None
    threshold: Optional[float] = Field(None, ge=0, le=100)
    action: Optional[str] = None
    tags: Optional[List[str]] = None


class DetectionRuleResponse(BaseModel):
    """Detection rule response"""
    id: str
    name: str
    description: str
    type: str
    enabled: bool
    conditions: Dict[str, Any]
    threshold: float
    action: str
    created_at: datetime
    updated_at: datetime
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    tags: List[str] = []


# ========================================
# AUDIT LOG SCHEMAS
# ========================================

class AuditLogItem(BaseModel):
    """Audit log item"""
    id: str
    admin_id: str
    admin_email: str
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    details: Dict[str, Any] = {}
    ip_address: Optional[str] = None
    created_at: datetime


class AuditLogResponse(BaseModel):
    """Paginated audit log response"""
    logs: List[AuditLogItem]
    total: int
    page: int
    limit: int
    pages: int


# ========================================
# COMMON RESPONSE SCHEMAS
# ========================================

class SuccessResponse(BaseModel):
    """Generic success response"""
    success: bool = True
    message: str


class ErrorResponse(BaseModel):
    """Generic error response"""
    success: bool = False
    error: str
    detail: Optional[str] = None
