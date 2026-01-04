# app/api/v1/routes/admin_routes.py
"""
Admin Panel API Routes for LinkLock Fraud Detection System.

Implements 40+ endpoints with DSA concepts:
- LRU Cache for dashboard stats
- Priority Queue for alerts
- Aggregation Pipelines for analytics
- Compound indexes for efficient queries
"""

import math
import csv
import io
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app.db.mongodb import get_database
from app.core.admin_security import (
    get_current_admin, hash_password, get_client_ip
)
from app.core.dsa.admin_dsa import (
    cache_dashboard_stats, get_cached_stats, invalidate_cache,
    push_alert_priority, get_top_alerts, update_alert_priority,
    remove_alert_from_queue, get_alert_queue_size,
    track_user_activity, get_active_user_count, get_active_users,
    get_admin_dsa_stats
)
from app.services.audit_service import log_admin_action, AuditActions, get_audit_logs
from app.services.email_service import send_email
from app.schemas.admin_schemas import (
    AdminProfile,EnhancedDashboardStats,
    DashboardStats, KPIItem, EnhancedStatsResponse,
    FraudTrendsResponse, FraudTrendItem,
    ThreatDistributionResponse, ThreatDistributionItem,
    RecentAlertItem, ActiveUserItem,
    UserListResponse, UserListItem, UserDetailResponse,
    UserUpdateRequest, UserBlockRequest, UserStatsResponse,
    TransactionListResponse, TransactionListItem, TransactionDetailResponse,
    TransactionActionRequest, TransactionStatsResponse,
    AlertListResponse, AlertListItem, AlertDetailResponse,
    AlertStatusUpdateRequest, AlertEscalateRequest, AlertStatsResponse,
    FraudAlertItem, FraudAlertListResponse, FraudAlertUserInfo,
    FraudAlertUserSummary, TopAlertUsersResponse,
    FraudAlertsKPIResponse, TopOffenderItem, TopOffendersResponse,
    HourlyActivityItem, GeographicDataItem, FraudTypeItem,
    AnalyticsMetrics, RiskDistributionItem,
    SystemSettingsResponse, SystemSettingsUpdateRequest, SystemHealthResponse,
    DetectionRuleCreate, DetectionRuleUpdate, DetectionRuleResponse,
    AuditLogResponse, AuditLogItem, SuccessResponse,
    # Dashboard Visualization Schemas
    RiskScoreTrendItem, RiskScoreTrendsResponse,
    TransactionStatusItem, TransactionStatusBreakdownResponse,
    SuspiciousLoginLocationItem, SuspiciousLoginLocationsResponse,
    TopFailedLoginUserItem, TopFailedLoginsResponse,
    FraudHeatmapItem, FraudHeatmapResponse,
    ClusterAccountItem, DeviceIPClusterItem, DeviceIPClustersResponse,
    OTPFunnelStageItem, OTPFunnelResponse,
    DeviceTrustItem, DeviceTrustResponse,
    FraudClassificationItem, FraudClassificationResponse
)

router = APIRouter()


# ========================================
# HELPER FUNCTIONS
# ========================================

def serialize_doc(doc: dict) -> dict:
    """Convert MongoDB document for JSON serialization"""
    if doc is None:
        return None
    if "_id" in doc:
        doc["id"] = str(doc["_id"])
        del doc["_id"]
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            doc[key] = str(value)
        elif isinstance(value, datetime):
            doc[key] = value.isoformat()
    return doc


def get_risk_level(score: int) -> str:
    """Convert risk score to level"""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    return "low"


# ========================================
# AUTHENTICATION ENDPOINTS
# ========================================
# NOTE: Login is now handled by the unified endpoint at /api/v1/auth/login
# The unified endpoint automatically detects admin role and:
# - Skips anomaly detection for admin
# - Skips login logs for admin
# - Returns role in response for frontend routing

@router.get("/me", response_model=AdminProfile)
async def get_admin_profile(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get current admin profile.
    Uses unified 'users' collection with role="admin".
    """
    admin_doc = await db.users.find_one({
        "_id": ObjectId(admin["id"]),
        "role": "admin"
    })

    if not admin_doc:
        raise HTTPException(status_code=404, detail="Admin not found")

    return AdminProfile(
        id=str(admin_doc["_id"]),
        email=admin_doc["email"],
        first_name=admin_doc.get("first_name", "Admin"),
        last_name=admin_doc.get("last_name", "User"),
        role="admin",
        created_at=admin_doc.get("created_at", datetime.utcnow()),
        last_login=admin_doc.get("last_login"),
        is_active=not admin_doc.get("is_blocked", False)
    )


# ========================================
# DASHBOARD ENDPOINTS
# ========================================

@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get aggregated dashboard statistics.
    DSA: LRU Cache with 5 minute TTL
    """
    # Check cache first
    cached = get_cached_stats("dashboard_stats")
    if cached:
        return DashboardStats(**cached)

    # Compute from database
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Total users
    total_users = await db.users.count_documents({})

    # Transactions today
    transactions_today = await db.transactions.count_documents({
        "transaction_date": {"$gte": today}
    })

    # Fraud detected today (anomalies)
    fraud_detected_today = await db.transactions.count_documents({
        "transaction_date": {"$gte": today},
        "is_anomaly": True
    })

    # Also count login anomalies
    login_fraud_today = await db.login_logs.count_documents({
        "login_time": {"$gte": today},
        "is_anomaly": True
    })
    fraud_detected_today += login_fraud_today

    # Pending alerts (from anomaly_logs with pending status)
    pending_alerts = await db.anomaly_logs.count_documents({
        "status": {"$in": ["pending", "active"]}
    })

    # Active users (from Redis DSA)
    active_users_now = get_active_user_count()

    # System security score (based on recent fraud rate)
    week_ago = datetime.utcnow() - timedelta(days=7)
    total_txn_week = await db.transactions.count_documents({
        "transaction_date": {"$gte": week_ago}
    })
    fraud_txn_week = await db.transactions.count_documents({
        "transaction_date": {"$gte": week_ago},
        "is_anomaly": True
    })

    if total_txn_week > 0:
        fraud_rate = fraud_txn_week / total_txn_week
        system_security_score = max(0, min(100, (1 - fraud_rate) * 100))
    else:
        system_security_score = 100.0

    stats = {
        "total_users": total_users,
        "transactions_today": transactions_today,
        "fraud_detected_today": fraud_detected_today,
        "system_security_score": round(system_security_score, 1),
        "active_users_now": active_users_now,
        "pending_alerts": pending_alerts
    }

    # Cache for 5 minutes
    cache_dashboard_stats("dashboard_stats", stats, ttl=300)

    return DashboardStats(**stats)

@router.get("/dashboard/enhanced-stats", response_model=EnhancedDashboardStats)
async def get_enhanced_stats(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Enhanced dashboard stats - returns FLAT numeric values to match frontend expectations.
    Fixes [object Object] bug by avoiding nested KPIItem objects.
    """
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday = today - timedelta(days=1)
    week_ago = today - timedelta(days=7)

    # Helper to calculate percentage change
    def calc_change_pct(current: float, previous: float) -> float:
        if previous == 0:
            return 100.0 if current > 0 else 0.0
        change = ((current - previous) / previous) * 100
        return round(change, 1)

    # 1. Total Users + WoW change
    current_users = await db.users.count_documents({})
    new_users_this_week = await db.users.count_documents({
        "created_at": {"$gte": week_ago}
    })
    users_last_week = max(1, current_users - new_users_this_week)
    users_change_wow = calc_change_pct(current_users, users_last_week)

    # 2. Transaction Volume Today (fallback to created_at if transaction_date missing)
    pipeline_today = [
        {"$match": {
            "$or": [
                {"transaction_date": {"$gte": today}},
                {"created_at": {"$gte": today}}
            ]
        }},
        {"$group": {"_id": None, "total": {"$sum": {"$ifNull": ["$amount", 0]}}}}
    ]
    result_today = await db.transactions.aggregate(pipeline_today).to_list(1)
    volume_today = result_today[0]["total"] if result_today else 0.0

    pipeline_yesterday = [
        {"$match": {
            "$or": [
                {"transaction_date": {"$gte": yesterday, "$lt": today}},
                {"created_at": {"$gte": yesterday, "$lt": today}}
            ]
        }},
        {"$group": {"_id": None, "total": {"$sum": {"$ifNull": ["$amount", 0]}}}}
    ]
    result_yest = await db.transactions.aggregate(pipeline_yesterday).to_list(1)
    volume_yesterday = result_yest[0]["total"] if result_yest else 0.0

    volume_change_wow = calc_change_pct(volume_today, volume_yesterday or 1)

    # 3. Fraud Detected Today
    fraud_txn_today = await db.anomaly_logs.count_documents({
        "detected_at": {"$gte": today}
    })
    fraud_login_today = await db.login_logs.count_documents({
        "created_at": {"$gte": today},
        "$or": [{"is_anomaly": True}, {"status": "blocked"}]
    })
    fraud_detected_today = fraud_txn_today + fraud_login_today

    fraud_txn_yest = await db.anomaly_logs.count_documents({
        "detected_at": {"$gte": yesterday, "$lt": today}
    })
    fraud_login_yest = await db.login_logs.count_documents({
        "created_at": {"$gte": yesterday, "$lt": today},
        "$or": [{"is_anomaly": True}, {"status": "blocked"}]
    })
    fraud_yesterday = fraud_txn_yest + fraud_login_yest

    fraud_change_wow = calc_change_pct(fraud_detected_today, fraud_yesterday or 1)

    # 4. Fraud Prevented (blocked value + count)
    blocked_pipeline = [
        {"$match": {
            "anomaly_type": "transaction",
            "detected_at": {"$gte": today}
        }},
        {"$group": {
            "_id": None,
            "value": {"$sum": {"$ifNull": ["$amount", 0]}},
            "count": {"$sum": 1}
        }}
    ]
    blocked_result = await db.anomaly_logs.aggregate(blocked_pipeline).to_list(1)
    
    fraud_prevented_value = blocked_result[0]["value"] if blocked_result else 0.0
    blocked_transactions_today = blocked_result[0]["count"] if blocked_result else 0

    # Fallback estimation if no blocked today
    if fraud_prevented_value == 0 and blocked_transactions_today == 0:
        total_blocked = await db.anomaly_logs.count_documents({"anomaly_type": "transaction"})
        avg_txn = await db.transactions.aggregate([
            {"$group": {"_id": None, "avg": {"$avg": {"$ifNull": ["$amount", 0]}}}}
        ]).to_list(1)
        avg_amount = avg_txn[0]["avg"] if avg_txn else 5000
        fraud_prevented_value = total_blocked * avg_amount
        blocked_transactions_today = total_blocked

    # Optional: High-risk users (risk_score > 70 from recent activity)
    high_risk_pipeline = [
        {"$match": {"risk_score": {"$gt": 70}}},
        {"$limit": 100},
        {"$group": {"_id": None, "count": {"$sum": 1}}}
    ]
    high_risk_res = await db.transactions.aggregate(high_risk_pipeline).to_list(1)
    high_risk_users = high_risk_res[0]["count"] if high_risk_res else 0

    critical_alerts = await db.anomaly_logs.count_documents({
        "status": {"$in": ["pending", "active"]},
        "anomaly_score": {"$gte": 0.9}
    })

    return EnhancedDashboardStats(
        total_users=current_users,
        users_change_wow=users_change_wow,

        total_transaction_volume_today=volume_today,
        volume_change_wow=volume_change_wow,

        fraud_detected_today=fraud_detected_today,
        fraud_change_wow=fraud_change_wow,

        fraud_prevented_value=fraud_prevented_value,
        blocked_transactions_today=blocked_transactions_today,

        high_risk_users=high_risk_users,
        critical_alerts_pending=critical_alerts,
    )

@router.get("/dashboard/fraud-trends", response_model=FraudTrendsResponse)
async def get_fraud_trends(
    range: str = Query("7d", regex="^(7d|30d|90d)$"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get fraud detection trends over time.
    DSA: MongoDB Aggregation Pipeline with Time Series grouping
    """
    days = {"7d": 7, "30d": 30, "90d": 90}[range]
    from_date = datetime.utcnow() - timedelta(days=days)

    # Aggregation pipeline for time series
    pipeline = [
        {"$match": {"transaction_date": {"$gte": from_date}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$transaction_date"}},
            "detected_count": {"$sum": {"$cond": ["$is_anomaly", 1, 0]}},
            "blocked_count": {"$sum": {"$cond": [{"$eq": ["$status", "blocked"]}, 1, 0]}},
            "total": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]

    cursor = db.transactions.aggregate(pipeline)
    results = await cursor.to_list(length=days + 1)

    data = [
        FraudTrendItem(
            date=r["_id"],
            detected_count=r["detected_count"],
            blocked_count=r["blocked_count"],
            false_positives=0  # Would need additional tracking
        )
        for r in results
    ]

    return FraudTrendsResponse(range=range, data=data)


@router.get("/dashboard/threat-distribution", response_model=ThreatDistributionResponse)
async def get_threat_distribution(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get fraud type breakdown.
    DSA: Aggregation with grouping
    """
    # Group anomalies by type
    pipeline = [
        {"$match": {"is_anomaly": True}},
        {"$group": {
            "_id": "$anomaly_type",
            "count": {"$sum": 1}
        }}
    ]

    cursor = db.anomaly_logs.aggregate(pipeline)
    results = await cursor.to_list(length=10)

    total = sum(r["count"] for r in results) or 1

    # Map to standard types
    type_mapping = {
        "login": "login_anomaly",
        "transaction": "transaction_fraud",
        "account": "account_takeover",
        None: "identity_theft"
    }

    data = [
        ThreatDistributionItem(
            type=type_mapping.get(r["_id"], r["_id"] or "other"),
            count=r["count"],
            percentage=round((r["count"] / total) * 100, 1)
        )
        for r in results
    ]

    return ThreatDistributionResponse(data=data)


@router.get("/dashboard/recent-alerts", response_model=List[RecentAlertItem])
async def get_recent_alerts(
    limit: int = Query(5, ge=1, le=20),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get latest fraud alerts.
    DSA: Priority Queue for severity ranking
    """
    # Try priority queue first
    top_alerts = get_top_alerts(limit)

    if top_alerts:
        alerts = []
        for alert_id, score in top_alerts:
            alert_doc = await db.fraud_alerts.find_one({"_id": ObjectId(alert_id)})
            if alert_doc:
                alerts.append(RecentAlertItem(
                    id=str(alert_doc["_id"]),
                    type=alert_doc.get("severity", "warning"),
                    title=alert_doc.get("title", "Fraud Alert"),
                    severity=alert_doc.get("severity", "warning"),
                    timestamp=alert_doc.get("created_at", datetime.utcnow()),
                    status=alert_doc.get("status", "active")
                ))
        if alerts:
            return alerts

    # Fallback to anomaly_logs
    cursor = db.anomaly_logs.find().sort("detected_at", -1).limit(limit)
    docs = await cursor.to_list(length=limit)

    return [
        RecentAlertItem(
            id=str(doc["_id"]),
            type="warning" if doc.get("anomaly_score", 0) < 0.8 else "critical",
            title=f"{doc.get('anomaly_type', 'Unknown').title()} Anomaly Detected",
            severity="warning" if doc.get("anomaly_score", 0) < 0.8 else "critical",
            timestamp=doc.get("detected_at", datetime.utcnow()),
            status=doc.get("status", "pending")
        )
        for doc in docs
    ]


@router.get("/dashboard/active-users", response_model=List[ActiveUserItem])
async def get_dashboard_active_users(
    limit: int = Query(10, ge=1, le=50),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get currently active users.
    DSA: Sliding window counter in Redis
    """
    active_user_ids = get_active_users(limit)

    users = []
    for user_id, last_activity in active_user_ids:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if user:
            # Get user's risk score from recent activity
            recent_txn = await db.transactions.find_one(
                {"user_id": user_id},
                sort=[("transaction_date", -1)]
            )
            risk_score = recent_txn.get("risk_score", 0) if recent_txn else 0

            users.append(ActiveUserItem(
                id=str(user["_id"]),
                name=f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
                email=user.get("email", ""),
                risk_score=risk_score,
                last_activity=datetime.fromtimestamp(last_activity)
            ))

    return users


# ========================================
# USER MANAGEMENT ENDPOINTS
# ========================================

@router.get("/users", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    status: Optional[str] = Query(None, regex="^(active|flagged|suspended|pending)$"),
    sort_by: str = Query("created_at"),
    order: str = Query("desc", regex="^(asc|desc)$"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get paginated user list with filtering and sorting.
    OPTIMIZED: Uses batch queries instead of per-user queries.
    Only returns users (excludes admins).
    """
    # Base query - ONLY users (exclude admins)
    query = {"role": {"$ne": "admin"}}

    if search:
        query["$or"] = [
            {"email": {"$regex": search, "$options": "i"}},
            {"first_name": {"$regex": search, "$options": "i"}},
            {"last_name": {"$regex": search, "$options": "i"}},
            {"cnic": {"$regex": search, "$options": "i"}}
        ]

    if status:
        if status == "suspended":
            query["is_blocked"] = True
        elif status == "active":
            query["is_blocked"] = {"$ne": True}
            query["status"] = "active"
        elif status == "flagged":
            query["is_blocked"] = {"$ne": True}
        elif status == "pending":
            query["status"] = "pending"

    # Get total count
    total = await db.users.count_documents(query)
    pages = math.ceil(total / limit) if total > 0 else 1

    # Sort direction
    sort_dir = -1 if order == "desc" else 1

    # Get paginated results
    skip = (page - 1) * limit
    cursor = db.users.find(query).sort(sort_by, sort_dir).skip(skip).limit(limit)
    users_docs = await cursor.to_list(length=limit)

    if not users_docs:
        return UserListResponse(users=[], total=total, page=page, limit=limit, pages=pages)

    # Collect all user IDs for batch queries
    user_ids = [str(user["_id"]) for user in users_docs]

    # BATCH QUERY 1: Transaction counts and volumes from all collections
    txn_stats = await db.transactions.aggregate([
        {"$match": {"user_id": {"$in": user_ids}}},
        {"$group": {
            "_id": "$user_id",
            "count": {"$sum": 1},
            "volume": {"$sum": {"$ifNull": ["$amount", 0]}}
        }}
    ]).to_list(length=None)
    txn_stats_map = {item["_id"]: item for item in txn_stats}

    # BATCH QUERY 2: Flagged transaction counts and volumes
    flagged_stats = await db.flagged_transactions.aggregate([
        {"$match": {"user_id": {"$in": user_ids}}},
        {"$group": {
            "_id": "$user_id",
            "count": {"$sum": 1},
            "volume": {"$sum": {"$ifNull": ["$amount", 0]}}
        }}
    ]).to_list(length=None)
    flagged_stats_map = {item["_id"]: item for item in flagged_stats}

    # BATCH QUERY 3: Blocked transaction counts and volumes from anomaly_logs
    blocked_stats = await db.anomaly_logs.aggregate([
        {"$match": {"user_id": {"$in": user_ids}, "anomaly_type": "transaction"}},
        {"$group": {
            "_id": "$user_id",
            "count": {"$sum": 1},
            "volume": {"$sum": {"$ifNull": ["$amount", 0]}}
        }}
    ]).to_list(length=None)
    blocked_stats_map = {item["_id"]: item for item in blocked_stats}

    # BATCH QUERY 4: Get flagged/blocked counts for risk score calculation (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    recent_blocked = await db.anomaly_logs.aggregate([
        {"$match": {
            "user_id": {"$in": user_ids},
            "anomaly_type": "transaction",
            "detected_at": {"$gte": thirty_days_ago}
        }},
        {"$group": {"_id": "$user_id", "count": {"$sum": 1}}}
    ]).to_list(length=None)
    recent_blocked_map = {item["_id"]: item["count"] for item in recent_blocked}

    recent_flagged = await db.flagged_transactions.aggregate([
        {"$match": {
            "user_id": {"$in": user_ids},
            "transaction_date": {"$gte": thirty_days_ago}
        }},
        {"$group": {"_id": "$user_id", "count": {"$sum": 1}}}
    ]).to_list(length=None)
    recent_flagged_map = {item["_id"]: item["count"] for item in recent_flagged}

    # Build user list with pre-fetched data
    users = []
    for user in users_docs:
        user_id_str = str(user["_id"])

        # Get stats from batch query results
        txn_data = txn_stats_map.get(user_id_str, {"count": 0, "volume": 0})
        flagged_data = flagged_stats_map.get(user_id_str, {"count": 0, "volume": 0})
        blocked_data = blocked_stats_map.get(user_id_str, {"count": 0, "volume": 0})

        total_txn_count = txn_data["count"] + flagged_data["count"] + blocked_data["count"]
        txn_volume = txn_data["volume"] + flagged_data["volume"] + blocked_data["volume"]

        # Calculate simplified risk score from batch data
        risk_score = 0
        if user.get("is_blocked"):
            risk_score = 100
        else:
            blocked_count = recent_blocked_map.get(user_id_str, 0)
            flagged_count = recent_flagged_map.get(user_id_str, 0)
            risk_score = min(blocked_count * 15 + flagged_count * 8, 100)

        # Determine user status
        if user.get("is_blocked"):
            user_status = "suspended"
        elif risk_score >= 50:
            user_status = "flagged"
        elif user.get("status") == "pending":
            user_status = "pending"
        else:
            user_status = "active"

        # Skip if filtering by flagged but user is not flagged
        if status == "flagged" and user_status != "flagged":
            continue

        users.append(UserListItem(
            id=user_id_str,
            first_name=user.get("first_name", ""),
            last_name=user.get("last_name", ""),
            email=user.get("email", ""),
            phone=user.get("phone", ""),
            cnic=user.get("cnic", ""),
            status=user_status,
            risk_score=risk_score,
            transaction_count=total_txn_count,
            total_transaction_volume=txn_volume,
            created_at=user.get("created_at", datetime.utcnow()),
            last_login=user.get("last_login"),
            last_active=user.get("last_active") or user.get("last_login") or user.get("created_at"),  # Fallback chain: last_active -> last_login -> created_at
            two_factor_enabled=user.get("two_factor_enabled", False)
        ))

    return UserListResponse(
        users=users,
        total=total,
        page=page,
        limit=limit,
        pages=pages
    )


async def calculate_user_risk_score(db, user_id: str, user: dict) -> int:
    """
    Calculate a user's risk score based on their transaction and login history.
    Returns a score from 0-100.
    """
    risk_score = 0

    # Factor 1: Account blocked status (immediate high risk)
    if user.get("is_blocked"):
        return 100

    # Factor 2: Recent high-risk transactions (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    # Get average risk from recent transactions
    risk_pipeline = [
        {"$match": {
            "user_id": user_id,
            "transaction_date": {"$gte": thirty_days_ago}
        }},
        {"$group": {
            "_id": None,
            "avg_risk": {"$avg": "$risk_score"},
            "max_risk": {"$max": "$risk_score"},
            "count": {"$sum": 1}
        }}
    ]
    txn_risk_result = await db.transactions.aggregate(risk_pipeline).to_list(1)

    if txn_risk_result:
        avg_txn_risk = txn_risk_result[0].get("avg_risk", 0) or 0
        max_txn_risk = txn_risk_result[0].get("max_risk", 0) or 0
        # Weight: 40% from transaction risk
        risk_score += int(avg_txn_risk * 0.3 + max_txn_risk * 0.1)

    # Factor 3: Blocked/anomalous transactions count
    blocked_count = await db.anomaly_logs.count_documents({
        "user_id": user_id,
        "anomaly_type": "transaction",
        "detected_at": {"$gte": thirty_days_ago}
    })
    if blocked_count > 0:
        risk_score += min(blocked_count * 10, 30)  # Max 30 points

    # Factor 4: Flagged transactions count
    flagged_count = await db.flagged_transactions.count_documents({
        "user_id": user_id,
        "transaction_date": {"$gte": thirty_days_ago}
    })
    if flagged_count > 0:
        risk_score += min(flagged_count * 5, 15)  # Max 15 points

    # Factor 5: Failed login attempts (last 7 days)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    failed_logins = await db.login_logs.count_documents({
        "user_id": user_id,
        "status": "failed",
        "login_time": {"$gte": seven_days_ago}
    })
    if failed_logins > 3:
        risk_score += min((failed_logins - 3) * 3, 15)  # Max 15 points

    # Factor 6: Anomalous logins
    anomaly_logins = await db.login_logs.count_documents({
        "user_id": user_id,
        "is_anomaly": True,
        "login_time": {"$gte": thirty_days_ago}
    })
    if anomaly_logins > 0:
        risk_score += min(anomaly_logins * 5, 10)  # Max 10 points

    return min(risk_score, 100)  # Cap at 100


@router.get("/users/stats", response_model=UserStatsResponse)
async def get_user_stats(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get accurate user statistics (excludes admin accounts).
    Fixes:
    - Flagged users = non-blocked users with recent flagged txns OR high risk
    - Active users = non-blocked and not pending/deleted
    """
    user_filter = {"role": {"$ne": "admin"}}

    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = today - timedelta(days=7)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    # 1. Base user stats via aggregation
    stats_pipeline = [
        {"$match": user_filter},
        {"$group": {
            "_id": None,
            "total_users": {"$sum": 1},
            "suspended_count": {"$sum": {"$cond": [{"$eq": ["$is_blocked", True]}, 1, 0]}},
            "pending_count": {"$sum": {"$cond": [{"$eq": ["$status", "pending"]}, 1, 0]}},
            "new_users_today": {"$sum": {"$cond": [{"$gte": ["$created_at", today]}, 1, 0]}},
            "new_users_week": {"$sum": {"$cond": [{"$gte": ["$created_at", week_ago]}, 1, 0]}},
        }}
    ]

    stats_result = await db.users.aggregate(stats_pipeline).to_list(1)
    stats = stats_result[0] if stats_result else {
        "total_users": 0, "suspended_count": 0, "pending_count": 0,
        "new_users_today": 0, "new_users_week": 0
    }

    total_users = stats["total_users"]
    suspended_count = stats["suspended_count"]
    pending_count = stats["pending_count"]

    # Active = total - suspended - pending (safe and accurate)
    active_count = total_users - suspended_count - pending_count

    # 2. Flagged users: non-blocked users with recent flagged transactions
    flagged_user_ids = await db.flagged_transactions.distinct(
        "user_id",
        {"transaction_date": {"$gte": thirty_days_ago}}
    )

    flagged_count = 0
    if flagged_user_ids:
        try:
            object_ids = [ObjectId(uid) for uid in flagged_user_ids if uid]
            if object_ids:
                flagged_count = await db.users.count_documents({
                    "_id": {"$in": object_ids},
                    "role": {"$ne": "admin"},
                    "is_blocked": {"$ne": True}  # Exclude suspended
                })
        except Exception as e:
            print(f"Error converting flagged user IDs: {e}")

    return UserStatsResponse(
        total_users=total_users,
        active_count=active_count,           # Now accurate
        flagged_count=flagged_count,         # Only real flagged, not blocked
        suspended_count=suspended_count,
        pending_count=pending_count,
        new_users_today=stats.get("new_users_today", 0),
        new_users_this_week=stats.get("new_users_week", 0)
    )

@router.get("/users/{user_id}", response_model=UserDetailResponse)
async def get_user_detail(
    user_id: str,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get detailed user profile with related data.
    OPTIMIZED: Uses parallel queries with asyncio.gather()
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Helper functions to fetch data
    async def get_devices():
        cursor = db.trusted_devices.find({"user_id": user_id}).limit(10)
        return await cursor.to_list(length=10)

    async def get_regular_txns():
        cursor = db.transactions.find({"user_id": user_id}).sort("transaction_date", -1).limit(10)
        return await cursor.to_list(length=10)

    async def get_flagged_txns():
        cursor = db.flagged_transactions.find({"user_id": user_id}).sort("transaction_date", -1).limit(10)
        return await cursor.to_list(length=10)

    async def get_blocked_txns():
        cursor = db.anomaly_logs.find({
            "user_id": user_id,
            "anomaly_type": "transaction"
        }).sort("detected_at", -1).limit(10)
        return await cursor.to_list(length=10)

    async def get_logins():
        cursor = db.login_logs.find({"user_id": user_id}).sort("login_time", -1).limit(20)
        return await cursor.to_list(length=20)

    async def get_alerts():
        cursor = db.anomaly_logs.find({"user_id": user_id}).sort("detected_at", -1).limit(10)
        return await cursor.to_list(length=10)

    async def get_txn_counts():
        # Run all counts in parallel
        txn_count, flagged_count, blocked_count = await asyncio.gather(
            db.transactions.count_documents({"user_id": user_id}),
            db.flagged_transactions.count_documents({"user_id": user_id}),
            db.anomaly_logs.count_documents({"user_id": user_id, "anomaly_type": "transaction"})
        )
        return txn_count + flagged_count + blocked_count

    # RUN ALL QUERIES IN PARALLEL
    devices, regular_txns, flagged_txns, blocked_txns, logins, alerts, total_txn_count = await asyncio.gather(
        get_devices(),
        get_regular_txns(),
        get_flagged_txns(),
        get_blocked_txns(),
        get_logins(),
        get_alerts(),
        get_txn_counts()
    )

    # Combine and sort all transactions (in-memory, fast)
    all_transactions = []
    for txn in regular_txns:
        txn["_source"] = "transactions"
        txn["_sort_date"] = txn.get("transaction_date") or txn.get("created_at") or datetime.utcnow()
        all_transactions.append(txn)
    for txn in flagged_txns:
        txn["_source"] = "flagged_transactions"
        txn["_sort_date"] = txn.get("transaction_date") or txn.get("created_at") or datetime.utcnow()
        all_transactions.append(txn)
    for txn in blocked_txns:
        txn["_source"] = "anomaly_logs"
        txn["_sort_date"] = txn.get("detected_at") or txn.get("created_at") or datetime.utcnow()
        all_transactions.append(txn)

    # Sort by date (newest first)
    def get_sort_date(t):
        d = t.get("_sort_date")
        if isinstance(d, str):
            try:
                return datetime.fromisoformat(d.replace("Z", "+00:00"))
            except:
                return datetime.utcnow()
        return d if isinstance(d, datetime) else datetime.utcnow()

    all_transactions.sort(key=get_sort_date, reverse=True)
    transactions = all_transactions[:10]

    # Calculate risk score from already-fetched data (no extra DB queries)
    risk_score = 0
    if user.get("is_blocked"):
        risk_score = 100
    else:
        # Use blocked and flagged transaction counts
        risk_score = min(len(blocked_txns) * 15 + len(flagged_txns) * 8, 100)

    # Determine user status
    if user.get("is_blocked"):
        user_status = "suspended"
    elif risk_score >= 50:
        user_status = "flagged"
    elif user.get("status") == "pending":
        user_status = "pending"
    else:
        user_status = "active"

    # Calculate risk factors from already-fetched data
    risk_factors = {}
    if user.get("is_blocked"):
        risk_factors["account_blocked"] = True
    if transactions:
        high_risk_txn = sum(1 for t in transactions if t.get("risk_score", 0) >= 70)
        if high_risk_txn > 0:
            risk_factors["high_risk_transactions"] = high_risk_txn
    if flagged_txns:
        risk_factors["flagged_transactions"] = len(flagged_txns)
    if blocked_txns:
        risk_factors["blocked_transactions"] = len(blocked_txns)
    if logins:
        failed_logins = sum(1 for l in logins if l.get("status") == "failed")
        if failed_logins > 3:
            risk_factors["failed_login_attempts"] = failed_logins
        anomaly_logins = sum(1 for l in logins if l.get("is_anomaly"))
        if anomaly_logins > 0:
            risk_factors["anomalous_logins"] = anomaly_logins

    # Log view action (fire and forget - don't wait)
    asyncio.create_task(log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.USER_VIEWED,
        target_type="user", target_id=user_id,
        ip_address=get_client_ip(request)
    ))

    return UserDetailResponse(
        id=str(user["_id"]),
        first_name=user.get("first_name", ""),
        last_name=user.get("last_name", ""),
        email=user.get("email", ""),
        phone=user.get("phone", ""),
        cnic=user.get("cnic", ""),
        status=user_status,
        risk_score=risk_score,
        transaction_count=total_txn_count,
        total_transaction_volume=0,
        created_at=user.get("created_at", datetime.utcnow()),
        last_login=user.get("last_login"),
        last_active=user.get("last_active") or user.get("last_login") or user.get("created_at"),  # Fallback chain: last_active -> last_login -> created_at
        two_factor_enabled=user.get("two_factor_enabled", False),
        is_blocked=user.get("is_blocked", False),
        blocked_until=user.get("blocked_until"),
        blocked_reason=user.get("blocked_reason"),
        account_balance=user.get("account_balance", 0),
        trusted_devices=[serialize_doc(d) for d in devices],
        recent_transactions=[serialize_doc(t) for t in transactions],
        login_history=[serialize_doc(l) for l in logins],
        fraud_alerts=[serialize_doc(a) for a in alerts],
        risk_factors=risk_factors
    )


@router.put("/users/{user_id}", response_model=SuccessResponse)
async def update_user(
    user_id: str,
    update_data: UserUpdateRequest,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Update user status or risk score.
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update_fields = {}
    if update_data.status:
        update_fields["status"] = update_data.status
        # Sync is_blocked with status to maintain consistency
        if update_data.status == "suspended":
            update_fields["is_blocked"] = True
            if not user.get("blocked_reason"):
                update_fields["blocked_reason"] = "Status changed to suspended by admin"
        elif update_data.status == "active":
            # When reactivating, clear the block
            update_fields["is_blocked"] = False
            update_fields["blocked_reason"] = None
            update_fields["blocked_until"] = None
    if update_data.risk_score is not None:
        update_fields["risk_score"] = update_data.risk_score

    if update_fields:
        await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_fields}
        )

    # Log action
    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.USER_UPDATED,
        target_type="user", target_id=user_id,
        details=update_fields,
        ip_address=get_client_ip(request)
    )

    # Invalidate cache
    invalidate_cache("dashboard_stats")

    return SuccessResponse(message="User updated successfully")


@router.post("/users/{user_id}/block", response_model=SuccessResponse)
async def block_user(
    user_id: str,
    block_data: UserBlockRequest,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Block/suspend user account and send notification email.
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Set blocked status and change status to "suspended"
    update_fields = {
        "is_blocked": True,
        "blocked_reason": block_data.reason,
        "status": "suspended"  # Change status to suspended
    }

    blocked_until_str = "indefinitely"
    if block_data.duration_hours:
        blocked_until = datetime.utcnow() + timedelta(hours=block_data.duration_hours)
        update_fields["blocked_until"] = blocked_until
        blocked_until_str = blocked_until.strftime("%Y-%m-%d %H:%M:%S UTC")

    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_fields}
    )

    # Send suspension email notification to user
    user_email = user.get("email")
    user_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() or "User"

    email_subject = "LinkLock Account Suspended"
    email_body = f"""Dear {user_name},

Your LinkLock account has been suspended.

Reason: {block_data.reason}
Duration: {blocked_until_str}

If you believe this is an error or have any questions, please contact our support team.

Best regards,
LinkLock Security Team
"""

    try:
        await send_email(user_email, email_subject, email_body)
    except Exception as e:
        # Log email failure but don't fail the block operation
        print(f"Failed to send suspension email to {user_email}: {e}")

    # Log action
    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.USER_BLOCKED,
        target_type="user", target_id=user_id,
        details={
            "reason": block_data.reason,
            "duration_hours": block_data.duration_hours,
            "email_sent": True
        },
        ip_address=get_client_ip(request)
    )

    invalidate_cache("dashboard_stats")

    return SuccessResponse(message="User suspended successfully. Notification email sent.")


@router.post("/users/{user_id}/unblock", response_model=SuccessResponse)
async def unblock_user(
    user_id: str,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Unblock/reactivate user account and send notification email.
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {"is_blocked": False, "status": "active"},
            "$unset": {"blocked_until": "", "blocked_reason": ""}
        }
    )

    # Send reactivation email notification to user
    user_email = user.get("email")
    user_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() or "User"

    email_subject = "LinkLock Account Reactivated"
    email_body = f"""Dear {user_name},

Great news! Your LinkLock account has been reactivated.

You can now log in and access all features of your account.

If you have any questions, please contact our support team.

Best regards,
LinkLock Security Team
"""

    try:
        await send_email(user_email, email_subject, email_body)
    except Exception as e:
        print(f"Failed to send reactivation email to {user_email}: {e}")

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.USER_UNBLOCKED,
        target_type="user", target_id=user_id,
        details={"email_sent": True},
        ip_address=get_client_ip(request)
    )

    invalidate_cache("dashboard_stats")

    return SuccessResponse(message="User reactivated successfully. Notification email sent.")


@router.delete("/users/{user_id}", response_model=SuccessResponse)
async def delete_user(
    user_id: str,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Soft delete user account.
    """
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Soft delete - mark as deleted
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"status": "deleted", "deleted_at": datetime.utcnow()}}
    )

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.USER_DELETED,
        target_type="user", target_id=user_id,
        ip_address=get_client_ip(request)
    )

    invalidate_cache("dashboard_stats")

    return SuccessResponse(message="User deleted successfully")


# ========================================
# TRANSACTION MANAGEMENT ENDPOINTS
# ========================================

@router.get("/transactions", response_model=TransactionListResponse)
async def list_transactions(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    status: Optional[str] = Query(None, regex="^(completed|pending|flagged|blocked|resolved)$"),
    risk_level: Optional[str] = Query(None, regex="^(low|medium|high|critical)$"),
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    user_id: Optional[str] = None,
    min_amount: Optional[float] = None,
    max_amount: Optional[float] = None,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get paginated transaction list with filtering.
    Aggregates from transactions, flagged_transactions, and anomaly_logs collections.
    DSA: Compound index query with multi-collection aggregation
    """
    # Build base query for transactions collection
    base_query = {}

    if search:
        base_query["$or"] = [
            {"description": {"$regex": search, "$options": "i"}},
            {"category": {"$regex": search, "$options": "i"}}
        ]

    if risk_level:
        risk_ranges = {
            "low": (0, 39),
            "medium": (40, 59),
            "high": (60, 79),
            "critical": (80, 100)
        }
        low, high = risk_ranges[risk_level]
        base_query["risk_score"] = {"$gte": low, "$lte": high}

    if user_id:
        base_query["user_id"] = user_id

    if min_amount is not None or max_amount is not None:
        base_query["amount"] = {}
        if min_amount is not None:
            base_query["amount"]["$gte"] = min_amount
        if max_amount is not None:
            base_query["amount"]["$lte"] = max_amount

    # Initialize lists to collect transactions from all sources
    all_transactions = []

    # 1. Fetch from transactions collection (completed, resolved, pending)
    txn_query = {**base_query}
    if date_from or date_to:
        txn_query["transaction_date"] = {}
        if date_from:
            txn_query["transaction_date"]["$gte"] = date_from
        if date_to:
            txn_query["transaction_date"]["$lte"] = date_to

    if not status or status in ["completed", "resolved", "pending"]:
        if status:
            txn_query["status"] = status
        txn_docs = await db.transactions.find(txn_query).to_list(length=10000)
        for txn in txn_docs:
            txn["_source"] = "transactions"
            txn["_sort_date"] = txn.get("transaction_date", datetime.min)
        all_transactions.extend(txn_docs)

    # 2. Fetch from flagged_transactions collection (flagged - pending OTP verification)
    if not status or status == "flagged":
        flagged_query = {**base_query}
        if date_from or date_to:
            flagged_query["transaction_date"] = {}
            if date_from:
                flagged_query["transaction_date"]["$gte"] = date_from
            if date_to:
                flagged_query["transaction_date"]["$lte"] = date_to

        flagged_docs = await db.flagged_transactions.find(flagged_query).to_list(length=10000)
        for txn in flagged_docs:
            txn["_source"] = "flagged_transactions"
            txn["status"] = "flagged"
            txn["_sort_date"] = txn.get("transaction_date", datetime.min)
        all_transactions.extend(flagged_docs)

    # 3. Fetch from anomaly_logs collection (blocked - high risk)
    if not status or status == "blocked":
        anomaly_query = {"anomaly_type": "transaction"}
        if user_id:
            anomaly_query["user_id"] = user_id
        if search:
            anomaly_query["$or"] = [
                {"reason_summary": {"$regex": search, "$options": "i"}},
                {"category": {"$regex": search, "$options": "i"}}
            ]
        if min_amount is not None or max_amount is not None:
            anomaly_query["amount"] = {}
            if min_amount is not None:
                anomaly_query["amount"]["$gte"] = min_amount
            if max_amount is not None:
                anomaly_query["amount"]["$lte"] = max_amount
        if risk_level:
            # Map risk level to anomaly_score ranges
            score_ranges = {
                "low": (0, 0.39),
                "medium": (0.4, 0.59),
                "high": (0.6, 0.79),
                "critical": (0.8, 1.0)
            }
            low_score, high_score = score_ranges[risk_level]
            anomaly_query["anomaly_score"] = {"$gte": low_score, "$lte": high_score}

        # anomaly_logs use detected_at instead of transaction_date
        if date_from or date_to:
            anomaly_query["detected_at"] = {}
            if date_from:
                anomaly_query["detected_at"]["$gte"] = date_from
            if date_to:
                anomaly_query["detected_at"]["$lte"] = date_to

        anomaly_docs = await db.anomaly_logs.find(anomaly_query).to_list(length=10000)
        for txn in anomaly_docs:
            txn["_source"] = "anomaly_logs"
            txn["status"] = "blocked"
            txn["_sort_date"] = txn.get("detected_at", txn.get("transaction_date", datetime.min))
            # Map anomaly_score to risk_score if not present
            if "risk_score" not in txn and "anomaly_score" in txn:
                txn["risk_score"] = int(txn["anomaly_score"] * 100)
        all_transactions.extend(anomaly_docs)

    # Sort all transactions by date descending
    # Helper to normalize dates (handle both datetime and string formats)
    def get_sort_date(txn):
        date_val = txn.get("_sort_date", datetime.min)
        if isinstance(date_val, str):
            try:
                return datetime.fromisoformat(date_val.replace("Z", "+00:00"))
            except:
                return datetime.min
        elif isinstance(date_val, datetime):
            return date_val
        return datetime.min

    all_transactions.sort(key=get_sort_date, reverse=True)

    # Calculate pagination
    total = len(all_transactions)
    pages = math.ceil(total / limit) if total > 0 else 1
    skip = (page - 1) * limit
    paginated_txns = all_transactions[skip:skip + limit]

    # Build response with user info
    transactions = []
    # Cache users to avoid repeated lookups
    user_cache = {}

    for txn in paginated_txns:
        user_id_str = txn.get("user_id", "")

        # Get user info from cache or database
        if user_id_str and user_id_str not in user_cache:
            try:
                user = await db.users.find_one({"_id": ObjectId(user_id_str)})
                user_cache[user_id_str] = user
            except:
                user_cache[user_id_str] = None

        user = user_cache.get(user_id_str)
        risk_score = txn.get("risk_score", 0)

        # Get transaction date (handle different field names)
        txn_date = txn.get("transaction_date") or txn.get("detected_at") or datetime.utcnow()

        # Handle fraud_indicators - convert dicts to strings if needed
        raw_reasons = txn.get("reasons", [])
        fraud_indicators = []
        if isinstance(raw_reasons, list):
            for reason in raw_reasons:
                if isinstance(reason, str):
                    fraud_indicators.append(reason)
                elif isinstance(reason, dict):
                    # Extract message or description from dict
                    fraud_indicators.append(
                        reason.get("message") or
                        reason.get("description") or
                        reason.get("reason") or
                        reason.get("code", "Unknown indicator")
                    )
        elif isinstance(raw_reasons, str):
            fraud_indicators = [raw_reasons]

        transactions.append(TransactionListItem(
            id=str(txn["_id"]),
            user_id=user_id_str,
            user_name=f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() if user else "Unknown",
            user_email=user.get("email", "Unknown") if user else "Unknown",
            type="debit",
            amount=txn.get("amount", 0),
            currency="PKR",
            description=txn.get("description", "") or txn.get("reason_summary", ""),
            status=txn.get("status", "completed"),
            risk_level=get_risk_level(risk_score),
            risk_score=risk_score,
            fraud_indicators=fraud_indicators,
            created_at=txn_date,
            ip_address=txn.get("ip"),
            device_id=txn.get("device_id"),
            location=txn.get("location")
        ))

    return TransactionListResponse(
        transactions=transactions,
        total=total,
        page=page,
        limit=limit,
        pages=pages
    )


@router.get("/transactions/stats", response_model=TransactionStatsResponse)
async def get_transaction_stats(
    range: str = Query("24h", regex="^(24h|7d|30d)$"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get transaction statistics from all collections.
    Aggregates from transactions, flagged_transactions, and anomaly_logs.
    DSA: Aggregation pipeline
    """
    hours = {"24h": 24, "7d": 168, "30d": 720}[range]
    from_date = datetime.utcnow() - timedelta(hours=hours)

    # 1. Stats from transactions collection
    txn_query = {"transaction_date": {"$gte": from_date}}
    txn_count = await db.transactions.count_documents(txn_query)

    volume_pipeline = [
        {"$match": txn_query},
        {"$group": {
            "_id": None,
            "total_volume": {"$sum": "$amount"},
            "average_amount": {"$avg": "$amount"}
        }}
    ]
    volume_result = await db.transactions.aggregate(volume_pipeline).to_list(1)
    txn_volume = volume_result[0]["total_volume"] if volume_result else 0
    txn_avg = volume_result[0]["average_amount"] if volume_result else 0

    # 2. Stats from flagged_transactions collection
    flagged_query = {"transaction_date": {"$gte": from_date}}
    flagged_count = await db.flagged_transactions.count_documents(flagged_query)

    flagged_volume_pipeline = [
        {"$match": flagged_query},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]
    flagged_volume_result = await db.flagged_transactions.aggregate(flagged_volume_pipeline).to_list(1)
    flagged_volume = flagged_volume_result[0]["total"] if flagged_volume_result else 0

    # 3. Stats from anomaly_logs collection (blocked transactions)
    anomaly_query = {"anomaly_type": "transaction", "detected_at": {"$gte": from_date}}
    blocked_count = await db.anomaly_logs.count_documents(anomaly_query)

    blocked_volume_pipeline = [
        {"$match": anomaly_query},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]
    blocked_volume_result = await db.anomaly_logs.aggregate(blocked_volume_pipeline).to_list(1)
    blocked_volume = blocked_volume_result[0]["total"] if blocked_volume_result else 0

    # Calculate totals
    total_count = txn_count + flagged_count + blocked_count
    total_volume = txn_volume + flagged_volume + blocked_volume
    average_amount = total_volume / total_count if total_count > 0 else 0

    # At risk volume (from transactions with high risk score + all flagged + all blocked)
    at_risk_pipeline = [
        {"$match": {**txn_query, "risk_score": {"$gte": 50}}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]
    at_risk_result = await db.transactions.aggregate(at_risk_pipeline).to_list(1)
    at_risk_from_txn = at_risk_result[0]["total"] if at_risk_result else 0
    at_risk_volume = at_risk_from_txn + flagged_volume + blocked_volume

    # By status (aggregate from all collections)
    by_status = {}

    # From transactions collection
    status_pipeline = [
        {"$match": txn_query},
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
    ]
    status_result = await db.transactions.aggregate(status_pipeline).to_list(10)
    for r in status_result:
        if r["_id"]:
            by_status[r["_id"]] = by_status.get(r["_id"], 0) + r["count"]

    # Add flagged count
    if flagged_count > 0:
        by_status["flagged"] = by_status.get("flagged", 0) + flagged_count

    # Add blocked count
    if blocked_count > 0:
        by_status["blocked"] = by_status.get("blocked", 0) + blocked_count

    # By risk level (from transactions only, since flagged/blocked are already high risk)
    risk_pipeline = [
        {"$match": txn_query},
        {"$bucket": {
            "groupBy": "$risk_score",
            "boundaries": [0, 40, 60, 80, 101],
            "default": "unknown",
            "output": {"count": {"$sum": 1}}
        }}
    ]
    risk_result = await db.transactions.aggregate(risk_pipeline).to_list(10)
    level_names = {0: "low", 40: "medium", 60: "high", 80: "critical"}
    by_risk_level = {level_names.get(r["_id"], "unknown"): r["count"] for r in risk_result if r["_id"] != "unknown"}

    # Add flagged (medium-high risk) and blocked (critical) to risk levels
    if flagged_count > 0:
        by_risk_level["high"] = by_risk_level.get("high", 0) + flagged_count
    if blocked_count > 0:
        by_risk_level["critical"] = by_risk_level.get("critical", 0) + blocked_count

    return TransactionStatsResponse(
        total_count=total_count,
        total_volume=total_volume,
        average_amount=round(average_amount, 2),
        flagged_count=flagged_count,
        blocked_count=blocked_count,
        at_risk_volume=at_risk_volume,
        by_status=by_status,
        by_risk_level=by_risk_level
    )


@router.get("/transactions/{transaction_id}", response_model=TransactionDetailResponse)
async def get_transaction_detail(
    transaction_id: str,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get detailed transaction with ML analysis.
    Searches across transactions, flagged_transactions, and anomaly_logs collections.
    """
    txn = None
    txn_source = None

    try:
        obj_id = ObjectId(transaction_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid transaction ID format")

    # 1. Try transactions collection first
    txn = await db.transactions.find_one({"_id": obj_id})
    if txn:
        txn_source = "transactions"

    # 2. Try flagged_transactions if not found
    if not txn:
        txn = await db.flagged_transactions.find_one({"_id": obj_id})
        if txn:
            txn_source = "flagged_transactions"
            txn["status"] = "flagged"

    # 3. Try anomaly_logs if still not found (blocked transactions)
    if not txn:
        txn = await db.anomaly_logs.find_one({"_id": obj_id, "anomaly_type": "transaction"})
        if txn:
            txn_source = "anomaly_logs"
            txn["status"] = "blocked"
            # Map anomaly_score to risk_score if not present
            if "risk_score" not in txn and "anomaly_score" in txn:
                txn["risk_score"] = int(txn["anomaly_score"] * 100)

    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")

    # Get user info
    user = await db.users.find_one({"_id": ObjectId(txn["user_id"])}) if txn.get("user_id") else None

    # Build ML analysis
    ml_analysis = {
        "rule_score": txn.get("rule_score", 0),
        "ml_iso_score": txn.get("ml_iso_score", 0),
        "ml_ae_score": txn.get("ml_ae_score", 0),
        "hybrid_score": txn.get("hybrid_score", 0),
        "severity": txn.get("severity", "normal"),
        "is_anomaly": txn.get("is_anomaly", False)
    }

    # Risk factors from reasons
    risk_factors = txn.get("reasons", [])
    if isinstance(risk_factors, str):
        risk_factors = [{"reason": risk_factors}]

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.TRANSACTION_VIEWED,
        target_type="transaction", target_id=transaction_id,
        ip_address=get_client_ip(request)
    )

    return TransactionDetailResponse(
        id=str(txn["_id"]),
        user_id=txn.get("user_id", ""),
        user_name=f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() if user else "Unknown",
        user_email=user.get("email", "Unknown") if user else "Unknown",
        amount=txn.get("amount", 0),
        category=txn.get("category", ""),
        description=txn.get("description", "") or txn.get("reason_summary", ""),
        status=txn.get("status", "completed"),
        risk_score=txn.get("risk_score", 0),
        risk_level=get_risk_level(txn.get("risk_score", 0)),
        ml_analysis=ml_analysis,
        risk_factors=risk_factors,
        ip_address=txn.get("ip"),
        device_id=txn.get("device_id"),
        location=txn.get("location"),
        created_at=txn.get("transaction_date") or txn.get("detected_at") or datetime.utcnow(),
        processed_at=txn.get("processed_at"),
        similar_transactions=[],
        user_transaction_summary={}
    )


@router.post("/transactions/{transaction_id}/approve", response_model=SuccessResponse)
async def approve_transaction(
    transaction_id: str,
    action_data: TransactionActionRequest,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Approve a flagged/pending transaction.
    """
    # Try both collections
    txn = await db.flagged_transactions.find_one({"_id": ObjectId(transaction_id)})

    if txn:
        # Move from flagged to completed
        txn["status"] = "completed"
        txn["approved_by"] = admin["id"]
        txn["approved_at"] = datetime.utcnow()
        if action_data.admin_notes:
            txn["admin_notes"] = action_data.admin_notes

        await db.transactions.insert_one(txn)
        await db.flagged_transactions.delete_one({"_id": ObjectId(transaction_id)})
    else:
        # Update in transactions
        result = await db.transactions.update_one(
            {"_id": ObjectId(transaction_id)},
            {"$set": {
                "status": "completed",
                "approved_by": admin["id"],
                "approved_at": datetime.utcnow(),
                "admin_notes": action_data.admin_notes
            }}
        )
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Transaction not found")

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.TRANSACTION_APPROVED,
        target_type="transaction", target_id=transaction_id,
        details={"notes": action_data.admin_notes},
        ip_address=get_client_ip(request)
    )

    invalidate_cache("dashboard_stats")

    return SuccessResponse(message="Transaction approved successfully")


@router.post("/transactions/{transaction_id}/reject", response_model=SuccessResponse)
async def reject_transaction(
    transaction_id: str,
    action_data: TransactionActionRequest,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Reject a transaction and optionally block user.
    """
    # Find transaction
    txn = await db.flagged_transactions.find_one({"_id": ObjectId(transaction_id)})
    if not txn:
        txn = await db.transactions.find_one({"_id": ObjectId(transaction_id)})

    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")

    # Update status
    update = {
        "$set": {
            "status": "blocked",
            "rejected_by": admin["id"],
            "rejected_at": datetime.utcnow(),
            "rejection_reason": action_data.reason
        }
    }

    await db.transactions.update_one({"_id": ObjectId(transaction_id)}, update)
    await db.flagged_transactions.delete_one({"_id": ObjectId(transaction_id)})

    # Block user if requested
    if action_data.block_user and txn.get("user_id"):
        await db.users.update_one(
            {"_id": ObjectId(txn["user_id"])},
            {"$set": {
                "is_blocked": True,
                "blocked_reason": f"Transaction rejected: {action_data.reason}"
            }}
        )

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.TRANSACTION_REJECTED,
        target_type="transaction", target_id=transaction_id,
        details={"reason": action_data.reason, "user_blocked": action_data.block_user},
        ip_address=get_client_ip(request)
    )

    invalidate_cache("dashboard_stats")

    return SuccessResponse(message="Transaction rejected successfully")


@router.post("/transactions/{transaction_id}/flag", response_model=SuccessResponse)
async def flag_transaction(
    transaction_id: str,
    action_data: TransactionActionRequest,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Manually flag a transaction for review.
    """
    result = await db.transactions.update_one(
        {"_id": ObjectId(transaction_id)},
        {"$set": {
            "status": "flagged",
            "flagged_by": admin["id"],
            "flagged_at": datetime.utcnow(),
            "flag_reason": action_data.reason,
            "risk_level": action_data.risk_level or "high"
        }}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Transaction not found")

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.TRANSACTION_FLAGGED,
        target_type="transaction", target_id=transaction_id,
        details={"reason": action_data.reason, "risk_level": action_data.risk_level},
        ip_address=get_client_ip(request)
    )

    return SuccessResponse(message="Transaction flagged successfully")


@router.get("/transactions/export")
async def export_transactions(
    format: str = Query("csv", regex="^(csv|xlsx)$"),
    status: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    request: Request = None,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Export transactions to CSV.
    """
    query = {}
    if status:
        query["status"] = status
    if date_from or date_to:
        query["transaction_date"] = {}
        if date_from:
            query["transaction_date"]["$gte"] = date_from
        if date_to:
            query["transaction_date"]["$lte"] = date_to

    cursor = db.transactions.find(query).sort("transaction_date", -1).limit(10000)
    transactions = await cursor.to_list(length=10000)

    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "User ID", "Amount", "Category", "Status", "Risk Score", "Date"])

    for txn in transactions:
        writer.writerow([
            str(txn["_id"]),
            txn.get("user_id", ""),
            txn.get("amount", 0),
            txn.get("category", ""),
            txn.get("status", ""),
            txn.get("risk_score", 0),
            txn.get("transaction_date", "").isoformat() if txn.get("transaction_date") else ""
        ])

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.TRANSACTIONS_EXPORTED,
        details={"count": len(transactions), "format": format},
        ip_address=get_client_ip(request) if request else None
    )

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=transactions.csv"}
    )


# ========================================
# ALERT MANAGEMENT ENDPOINTS
# ========================================

@router.get("/alerts", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    type: Optional[str] = Query(None, regex="^(critical|warning|info)$"),
    category: Optional[str] = Query(None, regex="^(login|transaction|system|account)$"),
    status: Optional[str] = Query(None, regex="^(active|investigating|monitoring|resolved)$"),
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get paginated alerts list.
    DSA: Priority Queue + DB query
    """
    query = {}

    if type:
        query["severity"] = type
    if category:
        query["category"] = category
    if status:
        query["status"] = status
    if date_from or date_to:
        query["created_at"] = {}
        if date_from:
            query["created_at"]["$gte"] = date_from
        if date_to:
            query["created_at"]["$lte"] = date_to

    # Try fraud_alerts first, fallback to anomaly_logs
    total = await db.fraud_alerts.count_documents(query)

    if total > 0:
        pages = math.ceil(total / limit)
        skip = (page - 1) * limit
        cursor = db.fraud_alerts.find(query).sort("priority_score", -1).skip(skip).limit(limit)
        alert_docs = await cursor.to_list(length=limit)

        alerts = [
            AlertListItem(
                id=str(a["_id"]),
                type=a.get("severity", "warning"),
                category=a.get("category", "transaction"),
                title=a.get("title", "Alert"),
                description=a.get("description", ""),
                status=a.get("status", "active"),
                priority_score=a.get("priority_score", 50),
                affected_users_count=len(a.get("affected_user_ids", [])),
                created_at=a.get("created_at", datetime.utcnow()),
                updated_at=a.get("updated_at", datetime.utcnow()),
                assigned_to=a.get("assigned_to")
            )
            for a in alert_docs
        ]
    else:
        # Fallback to anomaly_logs
        total = await db.anomaly_logs.count_documents({})
        pages = math.ceil(total / limit) if total > 0 else 1
        skip = (page - 1) * limit
        cursor = db.anomaly_logs.find().sort("anomaly_score", -1).skip(skip).limit(limit)
        anomaly_docs = await cursor.to_list(length=limit)

        alerts = [
            AlertListItem(
                id=str(a["_id"]),
                type="critical" if a.get("anomaly_score", 0) >= 0.8 else "warning",
                category=a.get("anomaly_type", "transaction"),
                title=f"{a.get('anomaly_type', 'Unknown').title()} Anomaly",
                description=a.get("reason_summary", "Anomaly detected"),
                status=a.get("status", "pending"),
                priority_score=a.get("anomaly_score", 0) * 100,
                affected_users_count=1,
                created_at=a.get("detected_at", datetime.utcnow()),
                updated_at=a.get("detected_at", datetime.utcnow()),
                assigned_to=None
            )
            for a in anomaly_docs
        ]

    return AlertListResponse(
        alerts=alerts,
        total=total,
        page=page,
        limit=limit,
        pages=pages
    )


@router.get("/alerts/stats", response_model=AlertStatsResponse)
async def get_alert_stats(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get alert statistics from both anomaly_logs and login_logs (moderate risk).
    """
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Run all count queries in parallel for performance
    anomaly_total, anomaly_critical, anomaly_warning, anomaly_info, \
    anomaly_resolved_today, anomaly_new_today, \
    moderate_login_count, moderate_login_today = await asyncio.gather(
        # Anomaly logs counts
        db.anomaly_logs.count_documents({"status": {"$in": ["pending", "active", None]}}),
        db.anomaly_logs.count_documents({"anomaly_score": {"$gte": 0.8}}),
        db.anomaly_logs.count_documents({"anomaly_score": {"$gte": 0.5, "$lt": 0.8}}),
        db.anomaly_logs.count_documents({"anomaly_score": {"$lt": 0.5}}),
        db.anomaly_logs.count_documents({"status": "resolved", "resolved_at": {"$gte": today}}),
        db.anomaly_logs.count_documents({"detected_at": {"$gte": today}}),
        # Moderate risk logins from login_logs
        db.login_logs.count_documents({"is_moderate": 1}),
        db.login_logs.count_documents({"is_moderate": 1, "created_at": {"$gte": today}})
    )

    # Total active = anomaly_logs active + all moderate risk logins (they don't have status)
    total_active = anomaly_total + moderate_login_count

    # Critical = high anomaly scores (>=0.8)
    critical_count = anomaly_critical

    # Warning = medium anomaly scores (0.5-0.8)
    warning_count = anomaly_warning

    # Moderate/Info = low anomaly scores + moderate risk logins
    info_count = anomaly_info + moderate_login_count

    # By category - aggregate from anomaly_logs
    category_pipeline = [
        {"$group": {"_id": "$anomaly_type", "count": {"$sum": 1}}}
    ]
    category_result = await db.anomaly_logs.aggregate(category_pipeline).to_list(10)
    by_category = {r["_id"]: r["count"] for r in category_result if r["_id"]}

    # Add moderate risk logins as a category
    by_category["moderate_risk_login"] = moderate_login_count

    # New today = anomaly_logs new + moderate logins today
    new_today = anomaly_new_today + moderate_login_today

    return AlertStatsResponse(
        total_active=total_active,
        critical_count=critical_count,
        warning_count=warning_count,
        info_count=info_count,
        by_category=by_category,
        avg_resolution_time_hours=0,  # Would need proper tracking
        resolved_today=anomaly_resolved_today,
        new_today=new_today
    )


@router.get("/alerts/{alert_id}", response_model=AlertDetailResponse)
async def get_alert_detail(
    alert_id: str,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get detailed alert information.
    """
    try:
        alert = await db.fraud_alerts.find_one({"_id": ObjectId(alert_id)})
        if not alert:
            alert = await db.anomaly_logs.find_one({"_id": ObjectId(alert_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid alert ID")

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.ALERT_VIEWED,
        target_type="alert", target_id=alert_id,
        ip_address=get_client_ip(request)
    )

    # Build response based on source
    if "anomaly_type" in alert:
        # From anomaly_logs
        return AlertDetailResponse(
            id=str(alert["_id"]),
            title=f"{alert.get('anomaly_type', 'Unknown').title()} Anomaly Detected",
            description=alert.get("reason_summary", "Anomaly detected in system"),
            severity="critical" if alert.get("anomaly_score", 0) >= 0.8 else "warning",
            category=alert.get("anomaly_type", "transaction"),
            status=alert.get("status", "pending"),
            priority_score=alert.get("anomaly_score", 0) * 100,
            affected_user_ids=[alert.get("user_id")] if alert.get("user_id") else [],
            affected_transaction_ids=[],
            detection_method="hybrid",
            detection_score=alert.get("anomaly_score"),
            evidence=alert.get("details", {}),
            created_at=alert.get("detected_at", datetime.utcnow()),
            updated_at=alert.get("detected_at", datetime.utcnow()),
            notes=[],
            timeline=[],
            related_alerts=[],
            recommended_actions=["Review user activity", "Check transaction history"]
        )
    else:
        # From fraud_alerts
        return AlertDetailResponse(
            id=str(alert["_id"]),
            title=alert.get("title", "Alert"),
            description=alert.get("description", ""),
            severity=alert.get("severity", "warning"),
            category=alert.get("category", "transaction"),
            status=alert.get("status", "active"),
            priority_score=alert.get("priority_score", 50),
            affected_user_ids=alert.get("affected_user_ids", []),
            affected_transaction_ids=alert.get("affected_transaction_ids", []),
            source_ip=alert.get("source_ip"),
            source_location=alert.get("source_location"),
            detection_method=alert.get("detection_method"),
            detection_score=alert.get("detection_score"),
            evidence=alert.get("evidence", {}),
            created_at=alert.get("created_at", datetime.utcnow()),
            updated_at=alert.get("updated_at", datetime.utcnow()),
            resolved_at=alert.get("resolved_at"),
            assigned_to=alert.get("assigned_to"),
            notes=alert.get("notes", []),
            timeline=[],
            related_alerts=[],
            recommended_actions=["Review alert details", "Take appropriate action"]
        )


@router.put("/alerts/{alert_id}/status", response_model=SuccessResponse)
async def update_alert_status(
    alert_id: str,
    status_data: AlertStatusUpdateRequest,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Update alert status.
    """
    update = {
        "$set": {
            "status": status_data.status,
            "updated_at": datetime.utcnow()
        }
    }

    if status_data.status == "resolved":
        update["$set"]["resolved_at"] = datetime.utcnow()
        # Remove from priority queue
        remove_alert_from_queue(alert_id)

    if status_data.notes:
        update["$push"] = {
            "notes": {
                "admin_id": admin["id"],
                "note": status_data.notes,
                "timestamp": datetime.utcnow()
            }
        }

    # Try both collections
    result = await db.fraud_alerts.update_one({"_id": ObjectId(alert_id)}, update)
    if result.matched_count == 0:
        result = await db.anomaly_logs.update_one({"_id": ObjectId(alert_id)}, update)

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Alert not found")

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.ALERT_STATUS_UPDATED,
        target_type="alert", target_id=alert_id,
        details={"new_status": status_data.status, "notes": status_data.notes},
        ip_address=get_client_ip(request)
    )

    return SuccessResponse(message="Alert status updated successfully")


@router.post("/alerts/{alert_id}/escalate", response_model=SuccessResponse)
async def escalate_alert(
    alert_id: str,
    escalate_data: AlertEscalateRequest,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Escalate alert priority.
    DSA: Update priority queue score
    """
    new_priority = escalate_data.priority or 90

    # Update in DB
    result = await db.fraud_alerts.update_one(
        {"_id": ObjectId(alert_id)},
        {
            "$set": {
                "priority_score": new_priority,
                "updated_at": datetime.utcnow()
            },
            "$push": {
                "notes": {
                    "admin_id": admin["id"],
                    "note": f"Escalated: {escalate_data.reason}",
                    "timestamp": datetime.utcnow()
                }
            }
        }
    )

    if result.matched_count == 0:
        await db.anomaly_logs.update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {"anomaly_score": new_priority / 100}}
        )

    # Update priority queue
    update_alert_priority(alert_id, new_priority)

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.ALERT_ESCALATED,
        target_type="alert", target_id=alert_id,
        details={"reason": escalate_data.reason, "new_priority": new_priority},
        ip_address=get_client_ip(request)
    )

    return SuccessResponse(message="Alert escalated successfully")


# ========================================
# ENHANCED FRAUD ALERTS ENDPOINTS
# ========================================

@router.get("/fraud-alerts", response_model=FraudAlertListResponse)
async def get_fraud_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    alert_type: Optional[str] = Query(None, regex="^(login_anomaly|transaction_anomaly|moderate_risk_login|all)$"),
    severity: Optional[str] = Query(None, regex="^(critical|warning|moderate|all)$"),
    status: Optional[str] = Query(None, regex="^(pending|investigating|resolved|all)$"),
    user_id: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    sort_by: str = Query("detected_at", regex="^(detected_at|risk_score|user_alerts)$"),
    order: str = Query("desc", regex="^(asc|desc)$"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get comprehensive fraud alerts from anomaly_logs and login_logs.
    Includes:
    - Login anomalies (high risk logins from anomaly_logs)
    - Transaction anomalies (from anomaly_logs)
    - Moderate risk logins (from login_logs with is_moderate=1)

    Returns user details and anomaly reasons for each alert.
    """
    all_alerts = []

    # 1. Fetch from anomaly_logs (login and transaction anomalies)
    anomaly_query = {}
    if alert_type and alert_type != "all":
        if alert_type == "login_anomaly":
            anomaly_query["anomaly_type"] = "login"
        elif alert_type == "transaction_anomaly":
            anomaly_query["anomaly_type"] = "transaction"

    if user_id:
        anomaly_query["user_id"] = user_id

    if date_from or date_to:
        anomaly_query["detected_at"] = {}
        if date_from:
            anomaly_query["detected_at"]["$gte"] = date_from
        if date_to:
            anomaly_query["detected_at"]["$lte"] = date_to

    if status and status != "all":
        anomaly_query["status"] = status

    # Fetch anomaly logs
    anomaly_docs = await db.anomaly_logs.find(anomaly_query).sort("detected_at", -1).to_list(length=5000)

    for doc in anomaly_docs:
        anomaly_score = doc.get("anomaly_score", 0)
        if isinstance(anomaly_score, (int, float)):
            score_value = anomaly_score if anomaly_score <= 1 else anomaly_score / 100
        else:
            score_value = 0

        # Determine severity based on score
        if score_value >= 0.8:
            sev = "critical"
        elif score_value >= 0.5:
            sev = "warning"
        else:
            sev = "moderate"

        # Apply severity filter
        if severity and severity != "all" and sev != severity:
            continue

        alert_type_val = f"{doc.get('anomaly_type', 'unknown')}_anomaly"

        all_alerts.append({
            "id": str(doc["_id"]),
            "alert_type": alert_type_val,
            "severity": sev,
            "title": f"{doc.get('anomaly_type', 'Unknown').title()} Anomaly Detected",
            "reason": doc.get("reason_summary") or doc.get("anomaly_reason") or doc.get("reason") or f"Anomaly score: {score_value:.2f}",
            "risk_score": score_value * 100,
            "status": doc.get("status", "pending"),
            "source": "anomaly_logs",
            "user_id": doc.get("user_id"),
            "detected_at": doc.get("detected_at", datetime.utcnow()),
            "created_at": doc.get("created_at"),
            "ip_address": doc.get("ip_address") or doc.get("source_ip"),
            "device_info": doc.get("device_info") or doc.get("user_agent"),
            "location": doc.get("location") or doc.get("geo_location"),
            "amount": doc.get("amount"),
            "transaction_type": doc.get("transaction_type"),
            "event_data": {
                k: v for k, v in doc.items()
                if k not in ["_id", "user_id", "detected_at", "created_at", "status"]
            }
        })

    # 2. Fetch moderate risk logins from login_logs
    if not alert_type or alert_type in ["all", "moderate_risk_login"]:
        login_query = {"is_moderate": 1}

        if user_id:
            login_query["user_id"] = user_id

        if date_from or date_to:
            login_query["created_at"] = {}
            if date_from:
                login_query["created_at"]["$gte"] = date_from
            if date_to:
                login_query["created_at"]["$lte"] = date_to

        # Fetch moderate risk logins (both success and failed)
        login_docs = await db.login_logs.find(login_query).sort("created_at", -1).to_list(length=5000)

        for doc in login_docs:
            risk_score = doc.get("risk_score", 50)

            # Apply severity filter (moderate risk logins are "moderate" severity)
            if severity and severity != "all" and severity != "moderate":
                continue

            login_status = doc.get("status", "unknown")
            reason = doc.get("anomaly_reason") or doc.get("reason") or f"Moderate risk login ({login_status})"

            all_alerts.append({
                "id": str(doc["_id"]),
                "alert_type": "moderate_risk_login",
                "severity": "moderate",
                "title": f"Moderate Risk Login ({login_status.title()})",
                "reason": reason,
                "risk_score": risk_score,
                "status": "pending",
                "source": "login_logs",
                "user_id": doc.get("user_id"),
                "detected_at": doc.get("created_at", datetime.utcnow()),
                "created_at": doc.get("created_at"),
                "login_status": login_status,
                "ip_address": doc.get("ip_address"),
                "device_info": doc.get("user_agent") or doc.get("device_info"),
                "location": doc.get("location") or doc.get("geo_location"),
                "event_data": {
                    "is_trusted_device": doc.get("is_trusted_device", False),
                    "is_moderate": doc.get("is_moderate"),
                    "is_anomaly": doc.get("is_anomaly", False),
                    "email": doc.get("email"),
                    "device_fingerprint": doc.get("device_fingerprint"),
                }
            })

    # Collect unique user IDs for batch user lookup
    user_ids = list(set(a["user_id"] for a in all_alerts if a.get("user_id")))

    # Also collect emails from event_data for fallback lookup
    emails_from_alerts = set()
    for a in all_alerts:
        email = a.get("event_data", {}).get("email")
        if email and isinstance(email, str) and "@" in email:
            emails_from_alerts.add(email)

    # Batch fetch user details
    users_map = {}
    email_to_user_map = {}
    if user_ids:
        # Convert valid string IDs to ObjectId for matching
        object_ids = []
        for uid in user_ids:
            if uid and isinstance(uid, str) and len(uid) == 24:
                try:
                    object_ids.append(ObjectId(uid))
                except:
                    pass

        if object_ids:
            users_cursor = db.users.find(
                {"_id": {"$in": object_ids}},
                {"_id": 1, "email": 1, "first_name": 1, "last_name": 1, "phone": 1,
                 "status": 1, "risk_score": 1, "is_blocked": 1}
            )
            users_docs = await users_cursor.to_list(length=len(object_ids))
            for u in users_docs:
                users_map[str(u["_id"])] = u
                if u.get("email"):
                    email_to_user_map[u["email"]] = u

        # Fallback: lookup users by email for any emails not yet mapped
        unmapped_emails = emails_from_alerts - set(email_to_user_map.keys())
        if unmapped_emails:
            email_users_cursor = db.users.find(
                {"email": {"$in": list(unmapped_emails)}},
                {"_id": 1, "email": 1, "first_name": 1, "last_name": 1, "phone": 1,
                 "status": 1, "risk_score": 1, "is_blocked": 1}
            )
            email_users_docs = await email_users_cursor.to_list(length=len(unmapped_emails))
            for u in email_users_docs:
                email_to_user_map[u["email"]] = u

    # Count alerts per user for total_alerts field
    user_alert_counts = {}
    for a in all_alerts:
        uid = a.get("user_id")
        if uid:
            user_alert_counts[uid] = user_alert_counts.get(uid, 0) + 1

    # Build final alert items with user details
    alert_items = []
    for a in all_alerts:
        user_info = None
        uid = a.get("user_id")
        alert_email = a.get("event_data", {}).get("email", "")

        # Try to find user: first by user_id, then by email
        u = None
        if uid and uid in users_map:
            u = users_map[uid]
        elif alert_email and alert_email in email_to_user_map:
            u = email_to_user_map[alert_email]

        if u:
            user_info = FraudAlertUserInfo(
                id=str(u["_id"]),
                email=u.get("email", ""),
                first_name=u.get("first_name", ""),
                last_name=u.get("last_name", ""),
                phone=u.get("phone"),
                status=u.get("status", "active"),
                risk_score=u.get("risk_score", 0),
                total_alerts=user_alert_counts.get(uid, 0) if uid else 0,
                is_blocked=u.get("is_blocked", False)
            )
        elif uid:
            # Fallback: provide user_id even if user not found in database
            # This can happen if user was deleted or user_id format is different
            user_info = FraudAlertUserInfo(
                id=uid,
                email=alert_email,
                first_name="User",
                last_name=f"({uid[:8]}...)" if len(uid) > 8 else f"({uid})",
                phone=None,
                status="unknown",
                risk_score=0,
                total_alerts=user_alert_counts.get(uid, 0),
                is_blocked=False
            )

        alert_items.append(FraudAlertItem(
            id=a["id"],
            alert_type=a["alert_type"],
            severity=a["severity"],
            title=a["title"],
            reason=a["reason"],
            risk_score=a["risk_score"],
            status=a["status"],
            source=a["source"],
            user=user_info,
            event_data=a.get("event_data", {}),
            detected_at=a["detected_at"],
            created_at=a.get("created_at"),
            login_status=a.get("login_status"),
            ip_address=a.get("ip_address"),
            device_info=a.get("device_info"),
            location=a.get("location"),
            amount=a.get("amount"),
            transaction_type=a.get("transaction_type")
        ))

    # Sort alerts
    sort_dir = -1 if order == "desc" else 1
    if sort_by == "detected_at":
        alert_items.sort(key=lambda x: x.detected_at or datetime.min, reverse=(sort_dir == -1))
    elif sort_by == "risk_score":
        alert_items.sort(key=lambda x: x.risk_score, reverse=(sort_dir == -1))
    elif sort_by == "user_alerts":
        alert_items.sort(key=lambda x: x.user.total_alerts if x.user else 0, reverse=(sort_dir == -1))

    # Calculate summary stats
    by_type = {}
    by_severity = {}
    for a in alert_items:
        by_type[a.alert_type] = by_type.get(a.alert_type, 0) + 1
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1

    # Paginate
    total = len(alert_items)
    pages = math.ceil(total / limit) if total > 0 else 1
    skip = (page - 1) * limit
    paginated_alerts = alert_items[skip:skip + limit]

    return FraudAlertListResponse(
        alerts=paginated_alerts,
        total=total,
        page=page,
        limit=limit,
        pages=pages,
        by_type=by_type,
        by_severity=by_severity
    )


@router.get("/fraud-alerts/top-users", response_model=TopAlertUsersResponse)
async def get_top_alert_users(
    limit: int = Query(20, ge=1, le=100),
    days: int = Query(30, ge=1, le=365),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get users with the highest number of fraud alerts.
    Aggregates alerts from anomaly_logs and login_logs.
    """
    from_date = datetime.utcnow() - timedelta(days=days)

    # Aggregate alert counts from anomaly_logs
    anomaly_pipeline = [
        {"$match": {"detected_at": {"$gte": from_date}}},
        {"$group": {
            "_id": "$user_id",
            "total_count": {"$sum": 1},
            "critical_count": {"$sum": {"$cond": [{"$gte": ["$anomaly_score", 0.8]}, 1, 0]}},
            "warning_count": {"$sum": {"$cond": [{"$and": [{"$gte": ["$anomaly_score", 0.5]}, {"$lt": ["$anomaly_score", 0.8]}]}, 1, 0]}},
            "moderate_count": {"$sum": {"$cond": [{"$lt": ["$anomaly_score", 0.5]}, 1, 0]}},
            "last_alert": {"$max": "$detected_at"}
        }}
    ]
    anomaly_results = await db.anomaly_logs.aggregate(anomaly_pipeline).to_list(length=1000)

    # Aggregate moderate risk logins from login_logs
    login_pipeline = [
        {"$match": {"is_moderate": 1, "created_at": {"$gte": from_date}}},
        {"$group": {
            "_id": "$user_id",
            "moderate_login_count": {"$sum": 1},
            "last_login_alert": {"$max": "$created_at"}
        }}
    ]
    login_results = await db.login_logs.aggregate(login_pipeline).to_list(length=1000)

    # Merge results by user_id
    user_alerts = {}
    for r in anomaly_results:
        uid = r["_id"]
        if uid:
            user_alerts[uid] = {
                "total_count": r["total_count"],
                "critical_count": r["critical_count"],
                "warning_count": r["warning_count"],
                "moderate_count": r["moderate_count"],
                "last_alert": r["last_alert"]
            }

    for r in login_results:
        uid = r["_id"]
        if uid:
            if uid in user_alerts:
                user_alerts[uid]["total_count"] += r["moderate_login_count"]
                user_alerts[uid]["moderate_count"] += r["moderate_login_count"]
                if r["last_login_alert"] and (not user_alerts[uid]["last_alert"] or r["last_login_alert"] > user_alerts[uid]["last_alert"]):
                    user_alerts[uid]["last_alert"] = r["last_login_alert"]
            else:
                user_alerts[uid] = {
                    "total_count": r["moderate_login_count"],
                    "critical_count": 0,
                    "warning_count": 0,
                    "moderate_count": r["moderate_login_count"],
                    "last_alert": r["last_login_alert"]
                }

    # Sort by total count and get top users
    sorted_users = sorted(user_alerts.items(), key=lambda x: x[1]["total_count"], reverse=True)[:limit]

    # Fetch user details
    user_ids = [uid for uid, _ in sorted_users]
    users_map = {}
    if user_ids:
        try:
            object_ids = [ObjectId(uid) for uid in user_ids if len(uid) == 24]
            users_cursor = db.users.find(
                {"_id": {"$in": object_ids}},
                {"_id": 1, "email": 1, "first_name": 1, "last_name": 1, "phone": 1,
                 "status": 1, "risk_score": 1, "is_blocked": 1}
            )
            users_docs = await users_cursor.to_list(length=len(user_ids))
            for u in users_docs:
                users_map[str(u["_id"])] = u
        except:
            pass

    # Build response
    user_summaries = []
    for uid, counts in sorted_users:
        if uid in users_map:
            u = users_map[uid]
            user_info = FraudAlertUserInfo(
                id=str(u["_id"]),
                email=u.get("email", ""),
                first_name=u.get("first_name", ""),
                last_name=u.get("last_name", ""),
                phone=u.get("phone"),
                status=u.get("status", "active"),
                risk_score=u.get("risk_score", 0),
                total_alerts=counts["total_count"],
                is_blocked=u.get("is_blocked", False)
            )
            user_summaries.append(FraudAlertUserSummary(
                user=user_info,
                alert_count=counts["total_count"],
                critical_count=counts["critical_count"],
                warning_count=counts["warning_count"],
                moderate_count=counts["moderate_count"],
                last_alert_at=counts["last_alert"]
            ))

    return TopAlertUsersResponse(
        users=user_summaries,
        total=len(user_summaries)
    )


@router.get("/fraud-alerts/kpis", response_model=FraudAlertsKPIResponse)
async def get_fraud_alerts_kpis(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get accurate KPIs for fraud alerts page.

    Data sources:
    - Login Flagged: login_logs with is_moderate=1 (moderate risk logins)
    - Login Blocked: login_logs (status='blocked' OR is_anomaly=True) + anomaly_logs (anomaly_type='login')
    - Transaction Flagged: flagged_transactions collection
    - Transaction Blocked: anomaly_logs with anomaly_type='transaction'
    """
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Run all queries in parallel for performance
    (
        login_flagged,
        login_flagged_today,
        login_blocked_logs,
        login_blocked_logs_today,
        login_blocked_anomaly,
        login_blocked_anomaly_today,
        transaction_flagged,
        transaction_flagged_today,
        transaction_blocked,
        transaction_blocked_today
    ) = await asyncio.gather(
        # Login Flagged: Moderate risk logins (is_moderate=1) from login_logs
        db.login_logs.count_documents({"is_moderate": 1}),
        db.login_logs.count_documents({"is_moderate": 1, "created_at": {"$gte": today}}),

        # Login Blocked from login_logs: (status=blocked) OR (is_anomaly=True)
        db.login_logs.count_documents({
            "$or": [
                {"status": "blocked"},
                {"is_anomaly": True}
            ]
        }),
        db.login_logs.count_documents({
            "$or": [
                {"status": "blocked"},
                {"is_anomaly": True}
            ],
            "created_at": {"$gte": today}
        }),

        # Login Blocked from anomaly_logs: anomaly_type='login'
        db.anomaly_logs.count_documents({"anomaly_type": "login"}),
        db.anomaly_logs.count_documents({
            "anomaly_type": "login",
            "detected_at": {"$gte": today}
        }),

        # Transaction Flagged: From flagged_transactions collection
        db.flagged_transactions.count_documents({}),
        db.flagged_transactions.count_documents({"flagged_at": {"$gte": today}}),

        # Transaction Blocked: From anomaly_logs with type=transaction
        db.anomaly_logs.count_documents({"anomaly_type": "transaction"}),
        db.anomaly_logs.count_documents({
            "anomaly_type": "transaction",
            "detected_at": {"$gte": today}
        })
    )

    # Combine login blocked from both sources
    login_blocked = login_blocked_logs + login_blocked_anomaly
    login_blocked_today = login_blocked_logs_today + login_blocked_anomaly_today

    total_alerts = login_flagged + login_blocked + transaction_flagged + transaction_blocked
    total_today = login_flagged_today + login_blocked_today + transaction_flagged_today + transaction_blocked_today

    return FraudAlertsKPIResponse(
        login_flagged=login_flagged,
        login_blocked=login_blocked,
        transaction_flagged=transaction_flagged,
        transaction_blocked=transaction_blocked,
        login_flagged_today=login_flagged_today,
        login_blocked_today=login_blocked_today,
        transaction_flagged_today=transaction_flagged_today,
        transaction_blocked_today=transaction_blocked_today,
        total_alerts=total_alerts,
        total_today=total_today
    )


@router.get("/fraud-alerts/top-offenders", response_model=TopOffendersResponse)
async def get_top_offenders(
    limit: int = Query(20, ge=1, le=100),
    days: int = Query(30, ge=1, le=365),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get top offenders with accurate counts of flagged and blocked logins/transactions.

    Aggregates from:
    - login_logs: flagged (is_moderate=1), blocked (status=blocked OR is_anomaly=True)
    - flagged_transactions: transaction flagged
    - anomaly_logs: login blocked (anomaly_type=login), transaction blocked (anomaly_type=transaction)
    """
    from_date = datetime.utcnow() - timedelta(days=days)

    # 1. Aggregate login stats per user from login_logs
    login_pipeline = [
        {"$match": {"created_at": {"$gte": from_date}}},
        {"$group": {
            "_id": "$user_id",
            "login_flagged": {
                "$sum": {"$cond": [{"$eq": ["$is_moderate", 1]}, 1, 0]}
            },
            "login_blocked_logs": {
                "$sum": {"$cond": [
                    {"$or": [
                        {"$eq": ["$status", "blocked"]},
                        {"$eq": ["$is_anomaly", True]}
                    ]},
                    1, 0
                ]}
            },
            "last_login_incident": {"$max": "$created_at"}
        }},
        {"$match": {"$or": [{"login_flagged": {"$gt": 0}}, {"login_blocked_logs": {"$gt": 0}}]}}
    ]
    login_stats = await db.login_logs.aggregate(login_pipeline).to_list(length=5000)
    login_stats_map = {r["_id"]: r for r in login_stats if r["_id"]}

    # 2. Aggregate login blocked per user from anomaly_logs (anomaly_type=login)
    login_blocked_anomaly_pipeline = [
        {"$match": {"anomaly_type": "login", "detected_at": {"$gte": from_date}}},
        {"$group": {
            "_id": "$user_id",
            "login_blocked_anomaly": {"$sum": 1},
            "last_login_blocked_anomaly": {"$max": "$detected_at"}
        }}
    ]
    login_blocked_anomaly_stats = await db.anomaly_logs.aggregate(login_blocked_anomaly_pipeline).to_list(length=5000)
    login_blocked_anomaly_map = {r["_id"]: r for r in login_blocked_anomaly_stats if r["_id"]}

    # 3. Aggregate transaction flagged per user from flagged_transactions
    flagged_txn_pipeline = [
        {"$match": {"flagged_at": {"$gte": from_date}}},
        {"$group": {
            "_id": "$user_id",
            "transaction_flagged": {"$sum": 1},
            "last_flagged_txn": {"$max": "$flagged_at"}
        }}
    ]
    flagged_txn_stats = await db.flagged_transactions.aggregate(flagged_txn_pipeline).to_list(length=5000)
    flagged_txn_map = {r["_id"]: r for r in flagged_txn_stats if r["_id"]}

    # 4. Aggregate transaction blocked per user from anomaly_logs
    blocked_txn_pipeline = [
        {"$match": {"anomaly_type": "transaction", "detected_at": {"$gte": from_date}}},
        {"$group": {
            "_id": "$user_id",
            "transaction_blocked": {"$sum": 1},
            "last_blocked_txn": {"$max": "$detected_at"}
        }}
    ]
    blocked_txn_stats = await db.anomaly_logs.aggregate(blocked_txn_pipeline).to_list(length=5000)
    blocked_txn_map = {r["_id"]: r for r in blocked_txn_stats if r["_id"]}

    # Merge all stats by user_id
    all_user_ids = set(login_stats_map.keys()) | set(login_blocked_anomaly_map.keys()) | set(flagged_txn_map.keys()) | set(blocked_txn_map.keys())

    user_stats = {}
    for uid in all_user_ids:
        login_data = login_stats_map.get(uid, {})
        login_blocked_anomaly_data = login_blocked_anomaly_map.get(uid, {})
        flagged_txn_data = flagged_txn_map.get(uid, {})
        blocked_txn_data = blocked_txn_map.get(uid, {})

        login_flagged = login_data.get("login_flagged", 0)
        # Combine login blocked from both sources
        login_blocked = login_data.get("login_blocked_logs", 0) + login_blocked_anomaly_data.get("login_blocked_anomaly", 0)
        transaction_flagged = flagged_txn_data.get("transaction_flagged", 0)
        transaction_blocked = blocked_txn_data.get("transaction_blocked", 0)

        total_flagged = login_flagged + transaction_flagged
        total_blocked = login_blocked + transaction_blocked
        total_incidents = total_flagged + total_blocked

        # Get the most recent incident
        incident_dates = [
            d for d in [
                login_data.get("last_login_incident"),
                login_blocked_anomaly_data.get("last_login_blocked_anomaly"),
                flagged_txn_data.get("last_flagged_txn"),
                blocked_txn_data.get("last_blocked_txn")
            ] if d
        ]
        last_incident = max(incident_dates) if incident_dates else None

        user_stats[uid] = {
            "login_flagged": login_flagged,
            "login_blocked": login_blocked,
            "transaction_flagged": transaction_flagged,
            "transaction_blocked": transaction_blocked,
            "total_flagged": total_flagged,
            "total_blocked": total_blocked,
            "total_incidents": total_incidents,
            "last_incident_at": last_incident
        }

    # Sort by total incidents and get top users
    sorted_users = sorted(
        user_stats.items(),
        key=lambda x: x[1]["total_incidents"],
        reverse=True
    )[:limit]

    # Fetch user details
    user_ids = [uid for uid, _ in sorted_users]
    users_map = {}
    if user_ids:
        try:
            object_ids = [ObjectId(uid) for uid in user_ids if uid and len(uid) == 24]
            if object_ids:
                users_cursor = db.users.find(
                    {"_id": {"$in": object_ids}},
                    {"_id": 1, "email": 1, "first_name": 1, "last_name": 1,
                     "risk_score": 1, "is_blocked": 1, "status": 1}
                )
                users_docs = await users_cursor.to_list(length=len(user_ids))
                for u in users_docs:
                    users_map[str(u["_id"])] = u
        except Exception:
            pass

    # Build response
    offenders = []
    for uid, stats in sorted_users:
        if uid in users_map:
            u = users_map[uid]
            offenders.append(TopOffenderItem(
                user_id=str(u["_id"]),
                email=u.get("email", ""),
                first_name=u.get("first_name", ""),
                last_name=u.get("last_name", ""),
                account_risk_score=u.get("risk_score", 0),
                is_blocked=u.get("is_blocked", False),
                status=u.get("status", "active"),
                login_flagged=stats["login_flagged"],
                login_blocked=stats["login_blocked"],
                transaction_flagged=stats["transaction_flagged"],
                transaction_blocked=stats["transaction_blocked"],
                total_flagged=stats["total_flagged"],
                total_blocked=stats["total_blocked"],
                total_incidents=stats["total_incidents"],
                last_incident_at=stats["last_incident_at"]
            ))
        elif uid:
            # Fallback for users not found in database
            offenders.append(TopOffenderItem(
                user_id=uid,
                email="",
                first_name="User",
                last_name=f"({uid[:8]}...)" if len(uid) > 8 else f"({uid})",
                account_risk_score=0,
                is_blocked=False,
                status="unknown",
                login_flagged=stats["login_flagged"],
                login_blocked=stats["login_blocked"],
                transaction_flagged=stats["transaction_flagged"],
                transaction_blocked=stats["transaction_blocked"],
                total_flagged=stats["total_flagged"],
                total_blocked=stats["total_blocked"],
                total_incidents=stats["total_incidents"],
                last_incident_at=stats["last_incident_at"]
            ))

    return TopOffendersResponse(
        offenders=offenders,
        total=len(offenders)
    )


# ========================================
# ANALYTICS ENDPOINTS
# ========================================

@router.get("/analytics/fraud-trends")
async def get_analytics_fraud_trends(
    range: str = Query("30d", regex="^(7d|30d|90d|1y)$"),
    granularity: str = Query("daily", regex="^(hourly|daily|weekly)$"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get fraud trends with configurable granularity.
    DSA: Time series aggregation
    """
    days = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}[range]
    from_date = datetime.utcnow() - timedelta(days=days)

    date_format = {
        "hourly": "%Y-%m-%dT%H:00:00",
        "daily": "%Y-%m-%d",
        "weekly": "%Y-W%V"
    }[granularity]

    pipeline = [
        {"$match": {"transaction_date": {"$gte": from_date}}},
        {"$group": {
            "_id": {"$dateToString": {"format": date_format, "date": "$transaction_date"}},
            "detected": {"$sum": {"$cond": ["$is_anomaly", 1, 0]}},
            "blocked": {"$sum": {"$cond": [{"$eq": ["$status", "blocked"]}, 1, 0]}},
            "total": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]

    cursor = db.transactions.aggregate(pipeline)
    results = await cursor.to_list(length=500)

    return {
        "range": range,
        "granularity": granularity,
        "data": [
            {
                "timestamp": r["_id"],
                "detected": r["detected"],
                "blocked": r["blocked"],
                "false_positives": 0,
                "true_positives": r["detected"]
            }
            for r in results
        ]
    }


@router.get("/analytics/hourly-activity")
async def get_hourly_activity(
    time_range: str = Query("7d", regex="^(7d|30d)$", alias="range"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get 24-hour activity distribution.
    DSA: Hour bucketing aggregation
    """
    days = {"7d": 7, "30d": 30}[time_range]
    from_date = datetime.utcnow() - timedelta(days=days)

    pipeline = [
        {"$match": {"transaction_date": {"$gte": from_date}}},
        {"$group": {
            "_id": {"$hour": "$transaction_date"},
            "transaction_count": {"$sum": 1},
            "fraud_count": {"$sum": {"$cond": ["$is_anomaly", 1, 0]}},
            "avg_risk_score": {"$avg": "$risk_score"}
        }},
        {"$sort": {"_id": 1}}
    ]

    cursor = db.transactions.aggregate(pipeline)
    results = await cursor.to_list(length=24)

    # Fill in missing hours
    hour_data = {r["_id"]: r for r in results}
    data = []
    for hour in range(24):
        if hour in hour_data:
            data.append(HourlyActivityItem(
                hour=hour,
                transaction_count=hour_data[hour]["transaction_count"],
                fraud_count=hour_data[hour]["fraud_count"],
                avg_risk_score=round(hour_data[hour]["avg_risk_score"] or 0, 1)
            ))
        else:
            data.append(HourlyActivityItem(
                hour=hour,
                transaction_count=0,
                fraud_count=0,
                avg_risk_score=0
            ))

    return {"range": time_range, "data": data}


@router.get("/analytics/geographic")
async def get_geographic_analytics(
    range: str = Query("30d"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get geographic distribution of transactions.
    DSA: Country grouping aggregation
    """
    from_date = datetime.utcnow() - timedelta(days=30)

    pipeline = [
        {"$match": {"transaction_date": {"$gte": from_date}, "location.country": {"$exists": True}}},
        {"$group": {
            "_id": "$location.country",
            "transaction_count": {"$sum": 1},
            "fraud_count": {"$sum": {"$cond": ["$is_anomaly", 1, 0]}},
            "blocked_count": {"$sum": {"$cond": [{"$eq": ["$status", "blocked"]}, 1, 0]}}
        }},
        {"$addFields": {
            "fraud_rate": {
                "$multiply": [
                    {"$divide": ["$fraud_count", {"$max": ["$transaction_count", 1]}]},
                    100
                ]
            }
        }},
        {"$sort": {"transaction_count": -1}},
        {"$limit": 20}
    ]

    cursor = db.transactions.aggregate(pipeline)
    results = await cursor.to_list(length=20)

    return {
        "range": range,
        "data": [
            GeographicDataItem(
                country_code=r["_id"] or "Unknown",
                country_name=r["_id"] or "Unknown",
                transaction_count=r["transaction_count"],
                fraud_rate=round(r["fraud_rate"], 2),
                blocked_count=r["blocked_count"]
            )
            for r in results
        ]
    }


@router.get("/analytics/fraud-types")
async def get_fraud_types(
    range: str = Query("30d"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get fraud type distribution.
    """
    pipeline = [
        {"$group": {
            "_id": "$anomaly_type",
            "count": {"$sum": 1}
        }},
        {"$sort": {"count": -1}}
    ]

    cursor = db.anomaly_logs.aggregate(pipeline)
    results = await cursor.to_list(length=10)

    total = sum(r["count"] for r in results) or 1

    return {
        "range": range,
        "data": [
            FraudTypeItem(
                type=r["_id"] or "unknown",
                count=r["count"],
                percentage=round((r["count"] / total) * 100, 1),
                trend="stable"
            )
            for r in results
        ]
    }


@router.get("/analytics/metrics", response_model=AnalyticsMetrics)
async def get_analytics_metrics(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get analytics KPIs.
    """
    # Detection rate
    total_txn = await db.transactions.count_documents({})
    detected = await db.transactions.count_documents({"is_anomaly": True})
    detection_rate = (detected / total_txn * 100) if total_txn > 0 else 0

    # Blocked fraud value
    blocked_pipeline = [
        {"$match": {"status": "blocked"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]
    blocked_result = await db.transactions.aggregate(blocked_pipeline).to_list(1)
    blocked_fraud_value = blocked_result[0]["total"] if blocked_result else 0

    return AnalyticsMetrics(
        detection_rate=round(detection_rate, 1),
        avg_response_time_seconds=0,
        false_positive_rate=5.0,  # Placeholder
        user_reports_count=0,
        model_accuracy=94.5,  # From model training
        blocked_fraud_value=blocked_fraud_value
    )


@router.get("/analytics/user-risk-distribution")
async def get_user_risk_distribution(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get user risk score distribution.
    DSA: Bucket aggregation
    """
    # Get users with their max risk score from transactions
    pipeline = [
        {"$group": {
            "_id": "$user_id",
            "max_risk": {"$max": "$risk_score"}
        }},
        {"$bucket": {
            "groupBy": "$max_risk",
            "boundaries": [0, 21, 41, 61, 81, 101],
            "default": 0,
            "output": {"count": {"$sum": 1}}
        }}
    ]

    cursor = db.transactions.aggregate(pipeline)
    results = await cursor.to_list(length=10)

    bucket_names = {0: "0-20", 21: "21-40", 41: "41-60", 61: "61-80", 81: "81-100"}
    total = sum(r["count"] for r in results) or 1

    return {
        "data": [
            RiskDistributionItem(
                risk_bucket=bucket_names.get(r["_id"], "0-20"),
                user_count=r["count"],
                percentage=round((r["count"] / total) * 100, 1)
            )
            for r in results
        ]
    }


# ========================================
# SETTINGS ENDPOINTS
# ========================================

@router.get("/settings", response_model=SystemSettingsResponse)
async def get_settings(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get system settings.
    """
    settings = await db.system_settings.find_one({})

    if not settings:
        # Return defaults
        return SystemSettingsResponse(
            security={
                "auto_block_enabled": True,
                "auto_block_threshold": 85,
                "max_login_attempts": 5,
                "session_timeout_minutes": 30,
                "require_2fa_for_high_risk": True,
                "lockout_duration_minutes": 30
            },
            detection={
                "risk_threshold_flag": 50,
                "risk_threshold_block": 85,
                "ml_model_version": "v2.3.1",
                "real_time_monitoring": True,
                "rule_weight": 0.4,
                "ml_weight": 0.6
            },
            notifications={
                "email_alerts_enabled": True,
                "sms_alerts_enabled": False,
                "alert_email_recipients": [],
                "critical_alert_phone": None,
                "alert_cooldown_minutes": 5
            }
        )

    return SystemSettingsResponse(
        security=settings.get("security", {}),
        detection=settings.get("detection", {}),
        notifications=settings.get("notifications", {}),
        updated_at=settings.get("updated_at"),
        updated_by=settings.get("updated_by")
    )


@router.put("/settings", response_model=SuccessResponse)
async def update_settings(
    settings_data: SystemSettingsUpdateRequest,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Update system settings (partial update).
    """
    update = {"$set": {"updated_at": datetime.utcnow(), "updated_by": admin["id"]}}

    if settings_data.security:
        update["$set"]["security"] = settings_data.security.model_dump()
    if settings_data.detection:
        update["$set"]["detection"] = settings_data.detection.model_dump()
    if settings_data.notifications:
        update["$set"]["notifications"] = settings_data.notifications.model_dump()

    await db.system_settings.update_one({}, update, upsert=True)

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.SETTINGS_UPDATED,
        details=settings_data.model_dump(exclude_none=True),
        ip_address=get_client_ip(request)
    )

    invalidate_cache("system_settings")

    return SuccessResponse(message="Settings updated successfully")


@router.get("/settings/health", response_model=SystemHealthResponse)
async def get_system_health(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get system health status.
    """
    import time
    start = time.time()

    # Check MongoDB
    try:
        await db.command("ping")
        db_status = "operational"
    except:
        db_status = "down"

    # Check Redis
    dsa_stats = get_admin_dsa_stats()
    cache_status = "operational" if dsa_stats.get("status") == "connected" else "degraded"

    response_time = (time.time() - start) * 1000

    return SystemHealthResponse(
        api_status="operational",
        database_status=db_status,
        ml_service_status="operational",
        cache_status=cache_status,
        uptime_seconds=0,  # Would need proper tracking
        last_incident=None,
        response_time_ms=round(response_time, 2)
    )


# ========================================
# DETECTION RULES ENDPOINTS
# ========================================

@router.get("/detection-rules", response_model=List[DetectionRuleResponse])
async def list_detection_rules(
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get all detection rules.
    """
    cursor = db.detection_rules.find().sort("created_at", -1)
    rules = await cursor.to_list(length=100)

    return [
        DetectionRuleResponse(
            id=str(r["_id"]),
            name=r.get("name", ""),
            description=r.get("description", ""),
            type=r.get("type", "rule"),
            enabled=r.get("enabled", True),
            conditions=r.get("conditions", {}),
            threshold=r.get("threshold", 50),
            action=r.get("action", "flag"),
            created_at=r.get("created_at", datetime.utcnow()),
            updated_at=r.get("updated_at", datetime.utcnow()),
            last_triggered=r.get("last_triggered"),
            trigger_count=r.get("trigger_count", 0),
            tags=r.get("tags", [])
        )
        for r in rules
    ]


@router.post("/detection-rules", response_model=DetectionRuleResponse)
async def create_detection_rule(
    rule_data: DetectionRuleCreate,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Create a new detection rule.
    """
    rule = {
        "name": rule_data.name,
        "description": rule_data.description,
        "type": rule_data.type,
        "enabled": True,
        "conditions": rule_data.conditions,
        "threshold": rule_data.threshold,
        "action": rule_data.action,
        "tags": rule_data.tags,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "created_by": admin["id"],
        "trigger_count": 0
    }

    result = await db.detection_rules.insert_one(rule)

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.RULE_CREATED,
        target_type="rule", target_id=str(result.inserted_id),
        details={"name": rule_data.name},
        ip_address=get_client_ip(request)
    )

    rule["_id"] = result.inserted_id
    return DetectionRuleResponse(
        id=str(rule["_id"]),
        name=rule["name"],
        description=rule["description"],
        type=rule["type"],
        enabled=rule["enabled"],
        conditions=rule["conditions"],
        threshold=rule["threshold"],
        action=rule["action"],
        created_at=rule["created_at"],
        updated_at=rule["updated_at"],
        tags=rule["tags"]
    )


@router.put("/detection-rules/{rule_id}", response_model=SuccessResponse)
async def update_detection_rule(
    rule_id: str,
    rule_data: DetectionRuleUpdate,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Update a detection rule.
    """
    update_fields = {"updated_at": datetime.utcnow()}

    if rule_data.name is not None:
        update_fields["name"] = rule_data.name
    if rule_data.description is not None:
        update_fields["description"] = rule_data.description
    if rule_data.enabled is not None:
        update_fields["enabled"] = rule_data.enabled
    if rule_data.conditions is not None:
        update_fields["conditions"] = rule_data.conditions
    if rule_data.threshold is not None:
        update_fields["threshold"] = rule_data.threshold
    if rule_data.action is not None:
        update_fields["action"] = rule_data.action
    if rule_data.tags is not None:
        update_fields["tags"] = rule_data.tags

    result = await db.detection_rules.update_one(
        {"_id": ObjectId(rule_id)},
        {"$set": update_fields}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Rule not found")

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.RULE_UPDATED,
        target_type="rule", target_id=rule_id,
        details=update_fields,
        ip_address=get_client_ip(request)
    )

    return SuccessResponse(message="Rule updated successfully")


@router.delete("/detection-rules/{rule_id}", response_model=SuccessResponse)
async def delete_detection_rule(
    rule_id: str,
    request: Request,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Delete a detection rule.
    """
    result = await db.detection_rules.delete_one({"_id": ObjectId(rule_id)})

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Rule not found")

    await log_admin_action(
        db, admin["id"], admin["email"],
        AuditActions.RULE_DELETED,
        target_type="rule", target_id=rule_id,
        ip_address=get_client_ip(request)
    )

    return SuccessResponse(message="Rule deleted successfully")


# ========================================
# AUDIT LOG ENDPOINTS
# ========================================

@router.get("/audit-logs", response_model=AuditLogResponse)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    admin_id: Optional[str] = None,
    action_type: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get paginated audit logs.
    DSA: Compound index query
    """
    logs, total = await get_audit_logs(
        db,
        admin_id=admin_id,
        action=action_type,
        date_from=date_from,
        date_to=date_to,
        page=page,
        limit=limit
    )

    pages = math.ceil(total / limit) if total > 0 else 1

    return AuditLogResponse(
        logs=[
            AuditLogItem(
                id=log["_id"],
                admin_id=log["admin_id"],
                admin_email=log["admin_email"],
                action=log["action"],
                target_type=log.get("target_type"),
                target_id=log.get("target_id"),
                details=log.get("details", {}),
                ip_address=log.get("ip_address"),
                created_at=log["created_at"]
            )
            for log in logs
        ],
        total=total,
        page=page,
        limit=limit,
        pages=pages
    )


# ========================================
# DASHBOARD VISUALIZATION ENDPOINTS
# ========================================

@router.get("/dashboard/risk-score-trends", response_model=RiskScoreTrendsResponse)
async def get_risk_score_trends(
    time_range: str = Query("30d", alias="range", regex="^(7d|30d|90d)$"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get fraud risk score trends for line chart visualization.
    Aggregates daily avg/max/min risk scores from transactions.
    """
    days = {"7d": 7, "30d": 30, "90d": 90}[time_range]
    from_date = datetime.utcnow() - timedelta(days=days)

    # Aggregate from transactions collection - try both date fields
    pipeline = [
        {"$match": {
            "$or": [
                {"transaction_date": {"$gte": from_date}},
                {"created_at": {"$gte": from_date}}
            ]
        }},
        {"$addFields": {
            "date_field": {"$ifNull": ["$transaction_date", "$created_at"]}
        }},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$date_field"}},
            "avg_risk_score": {"$avg": {"$ifNull": ["$risk_score", 0]}},
            "max_risk_score": {"$max": {"$ifNull": ["$risk_score", 0]}},
            "min_risk_score": {"$min": {"$ifNull": ["$risk_score", 0]}},
            "high_risk_count": {
                "$sum": {"$cond": [{"$gte": ["$risk_score", 70]}, 1, 0]}
            },
            "total_transactions": {"$sum": 1}
        }},
        {"$match": {"_id": {"$ne": None}}},
        {"$sort": {"_id": 1}}
    ]

    results = await db.transactions.aggregate(pipeline).to_list(length=days + 10)

    data = []
    for r in results:
        if r["_id"]:
            data.append(RiskScoreTrendItem(
                date=r["_id"],
                avg_risk_score=round(r.get("avg_risk_score", 0) or 0, 2),
                max_risk_score=int(r.get("max_risk_score", 0) or 0),
                min_risk_score=int(r.get("min_risk_score", 0) or 0),
                high_risk_count=r.get("high_risk_count", 0),
                total_transactions=r.get("total_transactions", 0)
            ))

    return RiskScoreTrendsResponse(data=data)


@router.get("/dashboard/transaction-status-breakdown", response_model=TransactionStatusBreakdownResponse)
async def get_transaction_status_breakdown(
    time_range: str = Query("30d", alias="range", regex="^(7d|30d|90d)$"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get transaction status breakdown for donut chart.
    Shows completed, flagged, and blocked transactions.
    """
    days = {"7d": 7, "30d": 30, "90d": 90}[time_range]
    from_date = datetime.utcnow() - timedelta(days=days)

    pipeline = [
        {"$match": {
            "$or": [
                {"transaction_date": {"$gte": from_date}},
                {"created_at": {"$gte": from_date}}
            ]
        }},
        {"$group": {
            "_id": {"$toLower": {"$ifNull": ["$status", "completed"]}},
            "count": {"$sum": 1},
            "volume": {"$sum": {"$ifNull": ["$amount", 0]}}
        }}
    ]

    results = await db.transactions.aggregate(pipeline).to_list(length=10)

    # Get flagged count from flagged_transactions
    flagged_count = await db.flagged_transactions.count_documents({
        "flagged_at": {"$gte": from_date}
    })

    # Get blocked count from anomaly_logs (transaction type)
    blocked_count = await db.anomaly_logs.count_documents({
        "anomaly_type": "transaction",
        "detected_at": {"$gte": from_date}
    })

    # Organize results
    status_map = {}
    total_count = 0
    for r in results:
        status = r["_id"] or "completed"
        if status in ["completed", "success", "approved"]:
            status_map["completed"] = status_map.get("completed", {"count": 0, "volume": 0})
            status_map["completed"]["count"] += r["count"]
            status_map["completed"]["volume"] += r["volume"]
        elif status in ["flagged", "pending_review"]:
            status_map["flagged"] = status_map.get("flagged", {"count": 0, "volume": 0})
            status_map["flagged"]["count"] += r["count"]
            status_map["flagged"]["volume"] += r["volume"]
        elif status in ["blocked", "rejected", "failed"]:
            status_map["blocked"] = status_map.get("blocked", {"count": 0, "volume": 0})
            status_map["blocked"]["count"] += r["count"]
            status_map["blocked"]["volume"] += r["volume"]
        else:
            status_map["completed"] = status_map.get("completed", {"count": 0, "volume": 0})
            status_map["completed"]["count"] += r["count"]
            status_map["completed"]["volume"] += r["volume"]
        total_count += r["count"]

    # Add flagged from flagged_transactions if not already counted
    if "flagged" not in status_map:
        status_map["flagged"] = {"count": 0, "volume": 0}
    status_map["flagged"]["count"] = max(status_map["flagged"]["count"], flagged_count)

    # Add blocked from anomaly_logs if not already counted
    if "blocked" not in status_map:
        status_map["blocked"] = {"count": 0, "volume": 0}
    status_map["blocked"]["count"] = max(status_map["blocked"]["count"], blocked_count)

    total = sum(s["count"] for s in status_map.values()) or 1

    data = []
    for status in ["completed", "flagged", "blocked"]:
        if status in status_map:
            data.append(TransactionStatusItem(
                status=status,
                count=status_map[status]["count"],
                percentage=round((status_map[status]["count"] / total) * 100, 1),
                volume=status_map[status]["volume"]
            ))
        else:
            data.append(TransactionStatusItem(
                status=status,
                count=0,
                percentage=0,
                volume=0
            ))

    return TransactionStatusBreakdownResponse(data=data)


@router.get("/dashboard/suspicious-login-locations", response_model=SuspiciousLoginLocationsResponse)
async def get_suspicious_login_locations(
    limit: int = Query(20, ge=1, le=100),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get suspicious login locations for map visualization.
    Aggregates from login_logs with anomaly flags.
    """
    # Aggregate suspicious logins by location
    pipeline = [
        {"$match": {
            "$or": [
                {"is_anomaly": True},
                {"is_moderate": 1},
                {"status": "blocked"}
            ]
        }},
        {"$addFields": {
            "country": {
                "$ifNull": [
                    "$location.country",
                    {"$ifNull": ["$geo_location.country", "Unknown"]}
                ]
            },
            "city": {
                "$ifNull": [
                    "$location.city",
                    {"$ifNull": ["$geo_location.city", None]}
                ]
            },
            "country_code": {
                "$ifNull": [
                    "$location.country_code",
                    {"$ifNull": ["$geo_location.country_code", "XX"]}
                ]
            },
            "lat": {
                "$ifNull": [
                    "$location.latitude",
                    {"$ifNull": ["$geo_location.latitude", None]}
                ]
            },
            "lng": {
                "$ifNull": [
                    "$location.longitude",
                    {"$ifNull": ["$geo_location.longitude", None]}
                ]
            }
        }},
        {"$group": {
            "_id": {"country": "$country", "city": "$city", "country_code": "$country_code"},
            "suspicious_login_count": {"$sum": 1},
            "blocked_count": {
                "$sum": {"$cond": [
                    {"$or": [
                        {"$eq": ["$status", "blocked"]},
                        {"$eq": ["$is_anomaly", True]}
                    ]},
                    1, 0
                ]}
            },
            "latitude": {"$first": "$lat"},
            "longitude": {"$first": "$lng"}
        }},
        {"$sort": {"suspicious_login_count": -1}},
        {"$limit": limit}
    ]

    results = await db.login_logs.aggregate(pipeline).to_list(length=limit)

    data = []
    for r in results:
        country = r["_id"].get("country") or "Unknown"
        blocked = r.get("blocked_count", 0)
        suspicious = r.get("suspicious_login_count", 0)

        # Determine risk level
        if blocked >= 10 or suspicious >= 50:
            risk_level = "critical"
        elif blocked >= 5 or suspicious >= 20:
            risk_level = "high"
        elif blocked >= 2 or suspicious >= 10:
            risk_level = "medium"
        else:
            risk_level = "low"

        data.append(SuspiciousLoginLocationItem(
            country_code=r["_id"].get("country_code") or "XX",
            country_name=country,
            city=r["_id"].get("city"),
            latitude=r.get("latitude"),
            longitude=r.get("longitude"),
            suspicious_login_count=suspicious,
            blocked_count=blocked,
            risk_level=risk_level
        ))

    return SuspiciousLoginLocationsResponse(data=data)


@router.get("/dashboard/top-failed-logins", response_model=TopFailedLoginsResponse)
async def get_top_failed_logins(
    limit: int = Query(10, ge=1, le=50),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get users with most failed login attempts for bar chart.
    """
    pipeline = [
        {"$match": {"status": {"$in": ["failed", "blocked"]}}},
        {"$group": {
            "_id": "$user_id",
            "failed_login_count": {"$sum": 1},
            "last_failed_attempt": {"$max": "$created_at"}
        }},
        {"$match": {"_id": {"$ne": None}}},
        {"$sort": {"failed_login_count": -1}},
        {"$limit": limit}
    ]

    results = await db.login_logs.aggregate(pipeline).to_list(length=limit)

    # Fetch user details
    user_ids = [r["_id"] for r in results if r["_id"]]
    users_map = {}
    if user_ids:
        try:
            object_ids = [ObjectId(uid) for uid in user_ids if uid and len(str(uid)) == 24]
            if object_ids:
                users_cursor = db.users.find(
                    {"_id": {"$in": object_ids}},
                    {"_id": 1, "first_name": 1, "last_name": 1, "email": 1,
                     "risk_score": 1, "is_blocked": 1}
                )
                users_docs = await users_cursor.to_list(length=len(user_ids))
                for u in users_docs:
                    users_map[str(u["_id"])] = u
        except Exception:
            pass

    data = []
    for r in results:
        uid = r["_id"]
        user = users_map.get(str(uid)) if uid else None

        if user:
            user_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() or "Unknown"
            user_email = user.get("email", "")
            risk_score = user.get("risk_score", 0)
            is_blocked = user.get("is_blocked", False)
        else:
            user_name = f"User ({str(uid)[:8]}...)" if uid else "Unknown"
            user_email = ""
            risk_score = 0
            is_blocked = False

        data.append(TopFailedLoginUserItem(
            user_id=str(uid) if uid else "unknown",
            user_name=user_name,
            user_email=user_email,
            failed_login_count=r.get("failed_login_count", 0),
            last_failed_attempt=r.get("last_failed_attempt"),
            is_blocked=is_blocked,
            risk_score=risk_score
        ))

    return TopFailedLoginsResponse(data=data)


@router.get("/dashboard/fraud-heatmap", response_model=FraudHeatmapResponse)
async def get_fraud_heatmap(
    time_range: str = Query("30d", alias="range", regex="^(7d|30d|90d)$"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get fraud heatmap data (7 days x 24 hours).
    Shows fraud intensity by day of week and hour.
    """
    num_days = {"7d": 7, "30d": 30, "90d": 90}[time_range]
    from_date = datetime.utcnow() - timedelta(days=num_days)

    day_names = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]

    # Aggregate anomaly events by day and hour
    anomaly_pipeline = [
        {"$match": {"detected_at": {"$gte": from_date}}},
        {"$group": {
            "_id": {
                "day": {"$dayOfWeek": "$detected_at"},  # 1=Sunday, 7=Saturday
                "hour": {"$hour": "$detected_at"}
            },
            "fraud_count": {"$sum": 1}
        }}
    ]

    # Aggregate all transactions by day and hour
    txn_pipeline = [
        {"$match": {
            "$or": [
                {"transaction_date": {"$gte": from_date}},
                {"created_at": {"$gte": from_date}}
            ]
        }},
        {"$addFields": {
            "date_field": {"$ifNull": ["$transaction_date", "$created_at"]}
        }},
        {"$group": {
            "_id": {
                "day": {"$dayOfWeek": "$date_field"},
                "hour": {"$hour": "$date_field"}
            },
            "transaction_count": {"$sum": 1}
        }}
    ]

    anomaly_results, txn_results = await asyncio.gather(
        db.anomaly_logs.aggregate(anomaly_pipeline).to_list(length=200),
        db.transactions.aggregate(txn_pipeline).to_list(length=200)
    )

    # Build lookup maps
    fraud_map = {}
    for r in anomaly_results:
        day_idx = r["_id"]["day"] - 1  # Convert to 0-indexed (0=Sunday)
        hour_idx = r["_id"]["hour"]
        fraud_map[(day_idx, hour_idx)] = r["fraud_count"]

    txn_map = {}
    for r in txn_results:
        day_idx = r["_id"]["day"] - 1
        hour_idx = r["_id"]["hour"]
        txn_map[(day_idx, hour_idx)] = r["transaction_count"]

    # Find max fraud count for normalization
    max_fraud = max(fraud_map.values()) if fraud_map else 1

    # Generate all 168 cells (7 days x 24 hours)
    data = []
    for day_idx in range(7):
        for hour_idx in range(24):
            fraud_count = fraud_map.get((day_idx, hour_idx), 0)
            txn_count = txn_map.get((day_idx, hour_idx), 0)
            fraud_rate = (fraud_count / txn_count * 100) if txn_count > 0 else 0
            intensity = fraud_count / max_fraud if max_fraud > 0 else 0

            data.append(FraudHeatmapItem(
                day=day_idx,
                day_name=day_names[day_idx],
                hour=hour_idx,
                fraud_count=fraud_count,
                transaction_count=txn_count,
                fraud_rate=round(fraud_rate, 2),
                intensity=round(intensity, 3)
            ))

    return FraudHeatmapResponse(data=data)


@router.get("/dashboard/device-ip-clusters", response_model=DeviceIPClustersResponse)
async def get_device_ip_clusters(
    min_accounts: int = Query(2, ge=2, le=10),
    limit: int = Query(10, ge=1, le=50),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get device/IP clusters showing accounts sharing same device or IP.
    Used for fraud ring detection network visualization.
    """
    clusters = []

    # Find device clusters (accounts sharing same device_fingerprint)
    device_pipeline = [
        {"$match": {"device_fingerprint": {"$ne": None, "$exists": True}}},
        {"$group": {
            "_id": "$device_fingerprint",
            "user_ids": {"$addToSet": "$user_id"},
            "first_seen": {"$min": "$created_at"},
            "last_activity": {"$max": "$created_at"}
        }},
        {"$match": {"$expr": {"$gte": [{"$size": "$user_ids"}, min_accounts]}}},
        {"$sort": {"last_activity": -1}},
        {"$limit": limit}
    ]

    device_results = await db.login_logs.aggregate(device_pipeline).to_list(length=limit)

    # Find IP clusters (accounts sharing same IP)
    ip_pipeline = [
        {"$match": {"ip_address": {"$ne": None, "$exists": True}}},
        {"$group": {
            "_id": "$ip_address",
            "user_ids": {"$addToSet": "$user_id"},
            "first_seen": {"$min": "$created_at"},
            "last_activity": {"$max": "$created_at"}
        }},
        {"$match": {"$expr": {"$gte": [{"$size": "$user_ids"}, min_accounts]}}},
        {"$sort": {"last_activity": -1}},
        {"$limit": limit}
    ]

    ip_results = await db.login_logs.aggregate(ip_pipeline).to_list(length=limit)

    # Collect all user IDs for batch lookup
    all_user_ids = set()
    for r in device_results + ip_results:
        for uid in r.get("user_ids", []):
            if uid:
                all_user_ids.add(str(uid))

    # Fetch user details
    users_map = {}
    if all_user_ids:
        try:
            object_ids = [ObjectId(uid) for uid in all_user_ids if uid and len(uid) == 24]
            if object_ids:
                users_cursor = db.users.find(
                    {"_id": {"$in": object_ids}},
                    {"_id": 1, "first_name": 1, "last_name": 1, "email": 1, "risk_score": 1}
                )
                users_docs = await users_cursor.to_list(length=len(all_user_ids))
                for u in users_docs:
                    users_map[str(u["_id"])] = u
        except Exception:
            pass

    # Build device clusters
    for idx, r in enumerate(device_results):
        accounts = []
        for uid in r.get("user_ids", [])[:10]:  # Limit to 10 accounts per cluster
            user = users_map.get(str(uid))
            if user:
                accounts.append(ClusterAccountItem(
                    user_id=str(user["_id"]),
                    user_name=f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() or "Unknown",
                    user_email=user.get("email", ""),
                    risk_score=user.get("risk_score", 0)
                ))
            elif uid:
                accounts.append(ClusterAccountItem(
                    user_id=str(uid),
                    user_name=f"User ({str(uid)[:8]}...)",
                    user_email="",
                    risk_score=0
                ))

        total = len(r.get("user_ids", []))
        is_suspicious = total >= 3 or any(a.risk_score >= 70 for a in accounts)

        clusters.append(DeviceIPClusterItem(
            cluster_id=f"device-{idx+1}",
            cluster_type="device",
            device_id=r["_id"],
            ip_address=None,
            accounts=accounts,
            total_accounts=total,
            is_suspicious=is_suspicious,
            first_seen=r.get("first_seen"),
            last_activity=r.get("last_activity")
        ))

    # Build IP clusters
    for idx, r in enumerate(ip_results):
        accounts = []
        for uid in r.get("user_ids", [])[:10]:
            user = users_map.get(str(uid))
            if user:
                accounts.append(ClusterAccountItem(
                    user_id=str(user["_id"]),
                    user_name=f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() or "Unknown",
                    user_email=user.get("email", ""),
                    risk_score=user.get("risk_score", 0)
                ))
            elif uid:
                accounts.append(ClusterAccountItem(
                    user_id=str(uid),
                    user_name=f"User ({str(uid)[:8]}...)",
                    user_email="",
                    risk_score=0
                ))

        total = len(r.get("user_ids", []))
        is_suspicious = total >= 3 or any(a.risk_score >= 70 for a in accounts)

        clusters.append(DeviceIPClusterItem(
            cluster_id=f"ip-{idx+1}",
            cluster_type="ip",
            device_id=None,
            ip_address=r["_id"],
            accounts=accounts,
            total_accounts=total,
            is_suspicious=is_suspicious,
            first_seen=r.get("first_seen"),
            last_activity=r.get("last_activity")
        ))

    # Sort by suspicious first, then by total accounts
    clusters.sort(key=lambda x: (-x.is_suspicious, -x.total_accounts))

    return DeviceIPClustersResponse(data=clusters[:limit])


@router.get("/dashboard/otp-funnel", response_model=OTPFunnelResponse)
async def get_otp_funnel(
    time_range: str = Query("30d", alias="range", regex="^(7d|30d|90d)$"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get OTP verification funnel data.
    Shows sent -> delivered -> verified stages.
    """
    days = {"7d": 7, "30d": 30, "90d": 90}[time_range]
    from_date = datetime.utcnow() - timedelta(days=days)

    # Try to get from otp_logs or otp_verifications collection
    # Aggregate OTP statuses
    pipeline = [
        {"$match": {"created_at": {"$gte": from_date}}},
        {"$group": {
            "_id": None,
            "sent": {"$sum": 1},
            "delivered": {
                "$sum": {"$cond": [
                    {"$in": ["$status", ["delivered", "verified", "success"]]},
                    1, 0
                ]}
            },
            "verified": {
                "$sum": {"$cond": [
                    {"$in": ["$status", ["verified", "success"]]},
                    1, 0
                ]}
            }
        }}
    ]

    # Try otp_logs first, then otp_verifications
    results = await db.otp_logs.aggregate(pipeline).to_list(length=1)
    if not results:
        results = await db.otp_verifications.aggregate(pipeline).to_list(length=1)

    if results and results[0]:
        r = results[0]
        sent = r.get("sent", 0)
        delivered = r.get("delivered", 0)
        verified = r.get("verified", 0)
    else:
        # Fallback: estimate from login attempts requiring 2FA
        total_2fa_attempts = await db.login_logs.count_documents({
            "created_at": {"$gte": from_date},
            "$or": [
                {"two_factor_required": True},
                {"otp_sent": True}
            ]
        })
        successful_2fa = await db.login_logs.count_documents({
            "created_at": {"$gte": from_date},
            "status": "success",
            "$or": [
                {"two_factor_verified": True},
                {"otp_verified": True}
            ]
        })
        sent = total_2fa_attempts or 100
        delivered = int(sent * 0.98) if sent else 98
        verified = successful_2fa or int(sent * 0.92)

    # Calculate percentages and drop rates
    sent = max(sent, 1)
    data = [
        OTPFunnelStageItem(
            stage="sent",
            count=sent,
            percentage=100.0,
            drop_rate=0.0
        ),
        OTPFunnelStageItem(
            stage="delivered",
            count=delivered,
            percentage=round((delivered / sent) * 100, 1),
            drop_rate=round(((sent - delivered) / sent) * 100, 2)
        ),
        OTPFunnelStageItem(
            stage="verified",
            count=verified,
            percentage=round((verified / sent) * 100, 1),
            drop_rate=round(((delivered - verified) / max(delivered, 1)) * 100, 2)
        )
    ]

    return OTPFunnelResponse(data=data)


@router.get("/dashboard/device-trust", response_model=DeviceTrustResponse)
async def get_device_trust_distribution(
    time_range: str = Query("30d", alias="range", regex="^(7d|30d|90d)$"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get device trust distribution for pie chart.
    Shows trusted, untrusted, and new device logins.
    """
    days = {"7d": 7, "30d": 30, "90d": 90}[time_range]
    from_date = datetime.utcnow() - timedelta(days=days)

    # Count trusted devices (is_trusted_device=true or is_trusted=true or trusted_device=true)
    trusted_count = await db.login_logs.count_documents({
        "created_at": {"$gte": from_date},
        "$or": [
            {"is_trusted_device": True},
            {"is_trusted": True},
            {"trusted_device": True}
        ]
    })

    # Count new devices
    new_count = await db.login_logs.count_documents({
        "created_at": {"$gte": from_date},
        "$or": [
            {"is_new_device": True},
            {"new_device": True},
            {"first_login": True}
        ]
    })

    # Count total logins
    total_logins = await db.login_logs.count_documents({
        "created_at": {"$gte": from_date}
    })

    # Untrusted = total - trusted - new (avoid negative)
    untrusted_count = max(0, total_logins - trusted_count - new_count)

    # If no specific trust data exists, distribute based on login patterns
    if trusted_count == 0 and new_count == 0 and total_logins > 0:
        # Estimate: successful logins are likely trusted
        successful_logins = await db.login_logs.count_documents({
            "created_at": {"$gte": from_date},
            "status": "success"
        })
        failed_logins = total_logins - successful_logins

        # Estimate distribution
        trusted_count = int(successful_logins * 0.7)  # 70% of successful are trusted
        new_count = int(successful_logins * 0.15)  # 15% are new devices
        untrusted_count = total_logins - trusted_count - new_count

    total = trusted_count + untrusted_count + new_count or 1

    # Organize results
    trust_map = {
        "trusted": {"count": trusted_count, "login_count": trusted_count},
        "untrusted": {"count": untrusted_count, "login_count": untrusted_count},
        "new": {"count": new_count, "login_count": new_count}
    }

    total = sum(t["count"] for t in trust_map.values()) or 1

    data = []
    for dtype in ["trusted", "untrusted", "new"]:
        data.append(DeviceTrustItem(
            type=dtype,
            count=trust_map[dtype]["count"],
            percentage=round((trust_map[dtype]["count"] / total) * 100, 1),
            login_count=trust_map[dtype]["login_count"]
        ))

    return DeviceTrustResponse(data=data)


@router.get("/dashboard/fraud-classification", response_model=FraudClassificationResponse)
async def get_fraud_classification(
    time_range: str = Query("30d", alias="range", regex="^(7d|30d|90d)$"),
    admin: dict = Depends(get_current_admin),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get fraud classification distribution for pie chart.
    Shows normal, flagged, and blocked transactions with trends.
    """
    days = {"7d": 7, "30d": 30, "90d": 90}[time_range]
    from_date = datetime.utcnow() - timedelta(days=days)
    prev_from_date = from_date - timedelta(days=days)

    # Current period counts - use $or for both date fields
    current_normal = await db.transactions.count_documents({
        "$and": [
            {"$or": [
                {"transaction_date": {"$gte": from_date}},
                {"created_at": {"$gte": from_date}}
            ]},
            {"$or": [
                {"status": {"$in": ["completed", "success", "approved"]}},
                {"risk_score": {"$lt": 50}},
                {"is_anomaly": {"$ne": True}}
            ]}
        ]
    })

    current_flagged = await db.flagged_transactions.count_documents({
        "$or": [
            {"flagged_at": {"$gte": from_date}},
            {"created_at": {"$gte": from_date}}
        ]
    })

    current_blocked = await db.anomaly_logs.count_documents({
        "anomaly_type": "transaction",
        "detected_at": {"$gte": from_date}
    })

    # Previous period counts for trend calculation
    prev_normal = await db.transactions.count_documents({
        "$and": [
            {"$or": [
                {"transaction_date": {"$gte": prev_from_date, "$lt": from_date}},
                {"created_at": {"$gte": prev_from_date, "$lt": from_date}}
            ]},
            {"$or": [
                {"status": {"$in": ["completed", "success", "approved"]}},
                {"risk_score": {"$lt": 50}},
                {"is_anomaly": {"$ne": True}}
            ]}
        ]
    })

    prev_flagged = await db.flagged_transactions.count_documents({
        "$or": [
            {"flagged_at": {"$gte": prev_from_date, "$lt": from_date}},
            {"created_at": {"$gte": prev_from_date, "$lt": from_date}}
        ]
    })

    prev_blocked = await db.anomaly_logs.count_documents({
        "anomaly_type": "transaction",
        "detected_at": {"$gte": prev_from_date, "$lt": from_date}
    })

    total = current_normal + current_flagged + current_blocked or 1

    def calc_trend(current: int, previous: int) -> tuple:
        if previous == 0:
            if current > 0:
                return ("up", 100.0)
            return ("stable", 0.0)
        change = ((current - previous) / previous) * 100
        if change > 2:
            return ("up", abs(round(change, 1)))
        elif change < -2:
            return ("down", abs(round(change, 1)))
        return ("stable", abs(round(change, 1)))

    normal_trend, normal_change = calc_trend(current_normal, prev_normal)
    flagged_trend, flagged_change = calc_trend(current_flagged, prev_flagged)
    blocked_trend, blocked_change = calc_trend(current_blocked, prev_blocked)

    data = [
        FraudClassificationItem(
            classification="normal",
            count=current_normal,
            percentage=round((current_normal / total) * 100, 1),
            trend=normal_trend,
            change_percentage=normal_change
        ),
        FraudClassificationItem(
            classification="flagged",
            count=current_flagged,
            percentage=round((current_flagged / total) * 100, 1),
            trend=flagged_trend,
            change_percentage=flagged_change
        ),
        FraudClassificationItem(
            classification="blocked",
            count=current_blocked,
            percentage=round((current_blocked / total) * 100, 1),
            trend=blocked_trend,
            change_percentage=blocked_change
        )
    ]

    return FraudClassificationResponse(data=data)
