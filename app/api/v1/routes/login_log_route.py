
# app/api/v1/routes/login_log_route.py

from fastapi import APIRouter, Depends, Request, HTTPException, Query
from app.schemas.login_log_schema import LoginLogCreate, LoginLogResponse
from app.utils.ip_utils import get_client_ip
from app.utils.geoip_utils import get_location_from_ip
from app.core.security import get_current_user
from app.db.mongodb import get_database
from typing import List, Optional
from datetime import datetime, timedelta
from bson import ObjectId

# Redis DSA imports (unused but kept for future)
from app.core.dsa.redis_dsa import (
    push_recent_login,
    record_login_attempt,
    set_last_ip,
    set_last_device
)

router = APIRouter(prefix="/login-logs", tags=["Login Logs"])


# ====================================================
#   GET MY LOGIN LOGS
# ====================================================
@router.get("/my-logs")
async def get_my_login_logs(
    limit: int = Query(default=50, le=100),
    skip: int = Query(default=0, ge=0),
    current_user=Depends(get_current_user),
    db=Depends(get_database)
):
    user_id = current_user["id"]

    logs_cursor = db.login_logs.find(
        {"user_id": user_id}
    ).sort("login_time", -1).skip(skip).limit(limit)

    logs = await logs_cursor.to_list(length=limit)

    for log in logs:
        log["_id"] = str(log["_id"])

    total = await db.login_logs.count_documents({"user_id": user_id})

    return {
        "logs": logs,
        "total": total,
        "limit": limit,
        "skip": skip
    }


# ====================================================
#   GET MY DEVICES
# ====================================================
@router.get("/my-devices")
async def get_my_devices(
    current_user=Depends(get_current_user),
    db=Depends(get_database)
):
    user_id = current_user["id"]

    pipeline = [
        {"$match": {"user_id": user_id, "status": "success"}},
        {"$sort": {"login_time": -1}},
        {
            "$group": {
                "_id": "$device_id",
                "device_name": {"$first": "$device_name"},
                "device_info": {"$first": "$device_info"},
                "last_used": {"$first": "$login_time"},
                "first_used": {"$last": "$login_time"},
                "login_count": {"$sum": 1},
                "locations": {"$addToSet": "$location.city"}
            }
        },
        {"$sort": {"last_used": -1}}
    ]

    devices = await db.login_logs.aggregate(pipeline).to_list(length=100)

    return {
        "devices": devices,
        "total": len(devices)
    }


# ====================================================
#   SUSPICIOUS ACTIVITY
# ====================================================
@router.get("/suspicious-activity")
async def get_suspicious_activity(
    days: int = Query(default=30, le=90),
    current_user=Depends(get_current_user),
    db=Depends(get_database)
):
    user_id = current_user["id"]
    since = datetime.utcnow() - timedelta(days=days)

    suspicious = await db.login_logs.find({
        "user_id": user_id,
        "login_time": {"$gte": since},
        "$or": [
            {"status": "failed"},
            {"is_anomaly": True},
            {"risk_score": {"$gte": 50}}
        ]
    }).sort("login_time", -1).to_list(length=100)

    for log in suspicious:
        log["_id"] = str(log["_id"])

    return {
        "suspicious_logins": suspicious,
        "count": len(suspicious)
    }


# ====================================================
#   LOGIN STATS
# ====================================================
@router.get("/stats")
async def get_login_stats(
    current_user=Depends(get_current_user),
    db=Depends(get_database)
):
    user_id = current_user["id"]

    total_logins = await db.login_logs.count_documents({"user_id": user_id})

    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    failed_logins = await db.login_logs.count_documents({
        "user_id": user_id,
        "status": "failed",
        "login_time": {"$gte": thirty_days_ago}
    })

    devices = await db.login_logs.distinct("device_id", {"user_id": user_id})

    locations = await db.login_logs.distinct("location.city", {
        "user_id": user_id,
        "location.city": {"$ne": None}
    })

    last_login = await db.login_logs.find_one(
        {"user_id": user_id, "status": "success"},
        sort=[("login_time", -1)]
    )

    return {
        "total_logins": total_logins,
        "failed_attempts_30d": failed_logins,
        "unique_devices": len(devices),
        "unique_locations": len(locations),
        "last_login": {
            "time": last_login["login_time"],
            "device": last_login.get("device_name"),
            "location": last_login.get("location", {}).get("city")
        } if last_login else None
    }


# ====================================================
#   ADMIN ENDPOINT (Open — must add admin role later)
# ====================================================
@router.get("/all", dependencies=[Depends(get_current_user)])
async def get_all_login_logs(
    limit: int = Query(default=100, le=500),
    skip: int = Query(default=0, ge=0),
    db=Depends(get_database)
):
    logs = await db.login_logs.find().sort("login_time", -1).skip(skip).limit(limit).to_list(length=limit)

    for log in logs:
        log["_id"] = str(log["_id"])

    total = await db.login_logs.count_documents({})

    return {
        "logs": logs,
        "total": total,
        "limit": limit,
        "skip": skip
    }
