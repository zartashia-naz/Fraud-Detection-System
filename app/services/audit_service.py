# app/services/audit_service.py
"""
Audit Logging Service for Admin Actions.

Provides complete audit trail for all admin operations.
Stores logs in MongoDB with proper indexing for efficient queries.
"""

from datetime import datetime
from typing import Optional, Any, Dict
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.db.models.audit_log_model import AuditLog


async def log_admin_action(
    db: AsyncIOMotorDatabase,
    admin_id: str,
    admin_email: str,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> str:
    """
    Log an admin action to the audit_logs collection.

    Args:
        db: MongoDB database instance
        admin_id: ID of the admin performing the action
        admin_email: Email of the admin
        action: Action type (e.g., "user_blocked", "transaction_approved")
        target_type: Type of target entity (e.g., "user", "transaction")
        target_id: ID of the target entity
        details: Additional details about the action
        ip_address: Admin's IP address
        user_agent: Admin's browser/client info

    Returns:
        str: ID of the created audit log entry
    """
    audit_log = AuditLog(
        admin_id=admin_id,
        admin_email=admin_email,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details or {},
        ip_address=ip_address,
        user_agent=user_agent,
        created_at=datetime.utcnow()
    )

    result = await db.audit_logs.insert_one(audit_log.model_dump())
    return str(result.inserted_id)


# Predefined action types for consistency
class AuditActions:
    """Standard audit action types"""

    # Authentication
    ADMIN_LOGIN = "admin_login"
    ADMIN_LOGOUT = "admin_logout"
    ADMIN_LOGIN_FAILED = "admin_login_failed"

    # User Management
    USER_VIEWED = "user_viewed"
    USER_UPDATED = "user_updated"
    USER_BLOCKED = "user_blocked"
    USER_UNBLOCKED = "user_unblocked"
    USER_DELETED = "user_deleted"

    # Transaction Management
    TRANSACTION_VIEWED = "transaction_viewed"
    TRANSACTION_APPROVED = "transaction_approved"
    TRANSACTION_REJECTED = "transaction_rejected"
    TRANSACTION_FLAGGED = "transaction_flagged"
    TRANSACTIONS_EXPORTED = "transactions_exported"

    # Alert Management
    ALERT_VIEWED = "alert_viewed"
    ALERT_STATUS_UPDATED = "alert_status_updated"
    ALERT_ESCALATED = "alert_escalated"
    ALERT_ASSIGNED = "alert_assigned"

    # Settings
    SETTINGS_VIEWED = "settings_viewed"
    SETTINGS_UPDATED = "settings_updated"

    # Detection Rules
    RULE_CREATED = "rule_created"
    RULE_UPDATED = "rule_updated"
    RULE_DELETED = "rule_deleted"

    # System
    SYSTEM_HEALTH_CHECKED = "system_health_checked"


async def get_audit_logs(
    db: AsyncIOMotorDatabase,
    admin_id: Optional[str] = None,
    action: Optional[str] = None,
    target_type: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    page: int = 1,
    limit: int = 50
) -> tuple:
    """
    Retrieve audit logs with filtering and pagination.

    Returns:
        tuple: (list of logs, total count)
    """
    query = {}

    if admin_id:
        query["admin_id"] = admin_id
    if action:
        query["action"] = action
    if target_type:
        query["target_type"] = target_type
    if date_from or date_to:
        query["created_at"] = {}
        if date_from:
            query["created_at"]["$gte"] = date_from
        if date_to:
            query["created_at"]["$lte"] = date_to

    # Get total count
    total = await db.audit_logs.count_documents(query)

    # Get paginated results
    skip = (page - 1) * limit
    cursor = db.audit_logs.find(query).sort("created_at", -1).skip(skip).limit(limit)
    logs = await cursor.to_list(length=limit)

    # Convert ObjectId to string
    for log in logs:
        log["_id"] = str(log["_id"])

    return logs, total


async def get_admin_activity_summary(
    db: AsyncIOMotorDatabase,
    admin_id: str,
    days: int = 30
) -> Dict[str, Any]:
    """
    Get activity summary for a specific admin.

    Returns aggregated counts by action type.
    """
    from datetime import timedelta

    date_from = datetime.utcnow() - timedelta(days=days)

    pipeline = [
        {
            "$match": {
                "admin_id": admin_id,
                "created_at": {"$gte": date_from}
            }
        },
        {
            "$group": {
                "_id": "$action",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {"count": -1}
        }
    ]

    cursor = db.audit_logs.aggregate(pipeline)
    results = await cursor.to_list(length=100)

    return {
        "admin_id": admin_id,
        "period_days": days,
        "actions": {r["_id"]: r["count"] for r in results},
        "total_actions": sum(r["count"] for r in results)
    }
