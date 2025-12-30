
from fastapi import APIRouter, Depends, Request, HTTPException
from datetime import datetime, timedelta
from typing import Optional
from bson import ObjectId
import numpy as np
from pydantic import BaseModel
from app.db.mongodb import get_database
from app.schemas.transaction_schema import TransactionCreate
from app.utils.geoip_utils import get_location_from_ip
from app.utils.ip_utils import get_client_ip
from app.utils.device_utils import get_device_id
from app.api.v1.routes.anomaly_route import handle_anomaly
from app.core.dsa.redis_dsa import push_recent_txn
from app.core.security import get_current_user
from app.hybrid_model.hybrid_transaction import hybrid_transaction_decision
from app.services.otp_service import create_or_resend_otp
from app.services.otp_verify_service import verify_otp
from app.services.email_service import send_email
import asyncio

# --------------------------------------------------
# Pydantic models
# --------------------------------------------------
class VerifyOTPRequest(BaseModel):
    otp: str
    transaction_id: str

class RequestOTPRequest(BaseModel):
    transaction_id: str

router = APIRouter(prefix="/transactions", tags=["Transactions"])

# --------------------------------------------------
# FEATURE ENGINEERING
# --------------------------------------------------
async def calculate_transaction_features(
    db, user_id: str, current_txn: dict, last_txn: dict = None
):
    now = current_txn["transaction_date"]
    amount = current_txn["amount"]
    
    hour = now.hour
    day_of_week = now.weekday()
    day = now.day
    
    one_hour_ago = now - timedelta(hours=1)
    twenty_four_hours_ago = now - timedelta(hours=24)
    
    tx_last_1hr = await db.transactions.count_documents({
        "user_id": user_id,
        "transaction_date": {"$gte": one_hour_ago, "$lt": now}
    })
    
    tx_last_24hr = await db.transactions.count_documents({
        "user_id": user_id,
        "transaction_date": {"$gte": twenty_four_hours_ago, "$lt": now}
    })
    
    user_txns = await db.transactions.find(
        {"user_id": user_id},
        {"amount": 1, "category": 1}
    ).to_list(length=1000)
    
    if user_txns:
        amounts = [t["amount"] for t in user_txns]
        mean_amount = np.mean(amounts)
        std_amount = np.std(amounts) if len(amounts) > 1 else 1.0
        amount_zscore = (amount - mean_amount) / std_amount if std_amount > 0 else 0.0
        
        category = current_txn["category"]
        cat_amounts = [t["amount"] for t in user_txns if t.get("category") == category]
        
        if cat_amounts:
            cat_mean = np.mean(cat_amounts)
            cat_std = np.std(cat_amounts) if len(cat_amounts) > 1 else 1.0
            category_amount_zscore = (amount - cat_mean) / cat_std if cat_std > 0 else 0.0
            category_usage_ratio = len(cat_amounts) / len(amounts)
            new_category_flag = 0
        else:
            category_amount_zscore = 0.0
            category_usage_ratio = 0.0
            new_category_flag = 1
        
        unique_categories = len(set(t.get("category") for t in user_txns if t.get("category")))
        unique_category_count = unique_categories
    else:
        amount_zscore = 0.0
        category_amount_zscore = 0.0
        category_usage_ratio = 0.0
        new_category_flag = 1
        unique_category_count = 1
    
    user_profile = await db.users.find_one({"_id": ObjectId(user_id)})
    account_balance = user_profile.get("account_balance", 10000.0) if user_profile else 10000.0
    amount_to_balance = amount / account_balance if account_balance > 0 else 0.0
    
    HIGH_RISK_CATEGORIES = ["Gambling", "Cryptocurrency", "International", "Cash Withdrawal"]
    high_risk_category = 1 if current_txn["category"] in HIGH_RISK_CATEGORIES else 0
    
    device_changed = 0
    ip_changed = 0
    location_changed = 0
    
    if last_txn:
        device_changed = 1 if current_txn.get("device_id") != last_txn.get("device_id") else 0
        ip_changed = 1 if current_txn.get("ip") != last_txn.get("ip") else 0
        
        curr_city = current_txn.get("location", {}).get("city")
        last_city = last_txn.get("location", {}).get("city")
        location_changed = 1 if curr_city and last_city and curr_city != last_city else 0
    
    login_attempts = 0
    
    enhanced_txn = {
        **current_txn,
        "hour": hour,
        "day_of_week": day_of_week,
        "day": day,
        "tx_last_1hr": tx_last_1hr,
        "tx_last_24hr": tx_last_24hr,
        "amount_zscore": amount_zscore,
        "amount_to_balance": amount_to_balance,
        "category_usage_ratio": category_usage_ratio,
        "new_category_flag": new_category_flag,
        "category_amount_zscore": category_amount_zscore,
        "unique_category_count": unique_category_count,
        "high_risk_category": high_risk_category,
        "device_changed": device_changed,
        "ip_changed": ip_changed,
        "location_changed": location_changed,
        "login_attempts": login_attempts,
        "account_balance": account_balance,
    }
    
    return enhanced_txn

# --------------------------------------------------
# CREATE TRANSACTION
# --------------------------------------------------
@router.post("")
async def create_transaction(
    request: Request,
    data: TransactionCreate,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    user_id = current_user["id"]
    email = current_user["email"]
    
    # Check if account is locked
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    locked_until = user.get("locked_until")
    if locked_until and locked_until > datetime.utcnow():
        raise HTTPException(
            status_code=403,
            detail=f"Account locked until {locked_until.isoformat()}. Please try again later."
        )
    
    ip_address = get_client_ip(request)
    device_id = get_device_id(request)
    location = get_location_from_ip(ip_address)
    
    last_txn = await db.transactions.find_one(
        {"user_id": user_id}, sort=[("_id", -1)]
    )
    
    prev_date = last_txn.get("transaction_date") if last_txn else None
    now = datetime.utcnow()
    transaction_duration = (
        (now - prev_date).total_seconds() if prev_date else None
    )
    
    merchant_id = f"MCT-{data.category[:3].upper()}-{user_id[:4]}"
    
    current_txn = {
        "user_id": user_id,
        "amount": data.amount,
        "category": data.category,
        "description": data.description,
        "ip": ip_address,
        "device_id": device_id,
        "location": location,
        "transaction_date": now,
        "transaction_duration": transaction_duration,
        "previous_transaction_date": prev_date,
    }
    
    enhanced_txn = await calculate_transaction_features(db, user_id, current_txn, last_txn)
    hybrid = hybrid_transaction_decision(enhanced_txn, last_txn)
    
    txn_dict = {
        **enhanced_txn,
        "merchant_id": merchant_id,
        "rule_flag": int(hybrid.get("rule_flag", 0)),
        "rule_score": float(hybrid.get("rule_score", 0.0)),
        "rule_details": hybrid.get("rule_details", {}),
        "ml_iso_score": float(hybrid.get("ml_iso_score", 0.0)),
        "ml_ae_score": float(hybrid.get("ml_ae_score", 0.0)),
        "ml_score": float(hybrid.get("ml_score", 0.0)),
        "hybrid_score": float(hybrid.get("hybrid_score", 0.0)),
        "is_moderate": int(hybrid.get("is_moderate", 0)),
        "is_anomaly": bool(hybrid.get("is_anomaly", False)),
        "severity": hybrid.get("severity", "normal"),
        "reasons": hybrid.get("reasons", []),
        "reason_summary": hybrid.get("reason_summary"),
        "risk_score": int(round(float(hybrid.get("hybrid_score", 0.0)) * 100)),
    }
    
    # ✅ Normal transaction
    if hybrid.get("severity") == "normal":
        txn_dict["status"] = "completed"
        result = await db.transactions.insert_one(txn_dict)
        txn_dict["_id"] = str(result.inserted_id)
        push_recent_txn(user_id, txn_dict)
        return {"message": "Transaction successful", "data": txn_dict}
    
    # ⚠️ Moderate risk - flagged for OTP verification
    if hybrid.get("is_moderate", 0) == 1:
        txn_dict["status"] = "flagged"
        result = await db.flagged_transactions.insert_one(txn_dict)
        txn_dict["_id"] = str(result.inserted_id)

        # Add push to Redis for flagged transaction
        try:
            push_recent_txn(user_id, txn_dict)
        except Exception:
            pass

        return {
            "message": "Transaction flagged for verification. Click 'Request OTP' to receive a verification code on your email.",
            "data": txn_dict
        }
    
    # 🚨 High risk - blocked
    txn_dict["status"] = "blocked"
    
    # ✅ SAVE TO ANOMALY_LOGS
    txn_id = await handle_anomaly(
        {
            "is_anomaly": True,
            "event_type": "transaction",
            "event_data": txn_dict,
        },
        db,
    )
    txn_dict["_id"] = txn_id

    # Add push to Redis for blocked transaction
    try:
        push_recent_txn(user_id, txn_dict)
    except Exception:
        pass
    
    # Fetch the reason_summary from anomaly_logs
    anomaly_log = await db.anomaly_logs.find_one({"_id": ObjectId(txn_id)})
    reason_summary = anomaly_log.get("reason_summary") if anomaly_log else "suspicious activity detected"
    
    # Lock account for 3 hours
    lock_until = datetime.utcnow() + timedelta(hours=3)
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"locked_until": lock_until}}
    )
    
    # Send email notification
    email_subject = "Account Temporarily Locked"
    email_body = f"""
Dear {user.get('first_name', 'User')},

Your account has been temporarily locked for 3 hours due to {reason_summary}.

If this wasn't you, please contact support immediately.

Regards,
Your Security Team
    """
    asyncio.create_task(send_email(email, email_subject, email_body))
    
    return {"message": "Transaction blocked due to high risk", "data": txn_dict}

# --------------------------------------------------
# REQUEST OTP (manual send + resend)
# --------------------------------------------------
@router.post("/request-otp")
async def request_transaction_otp(
    payload: RequestOTPRequest,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    user_id = current_user["id"]
    email = current_user["email"]
    
    txn = await db.flagged_transactions.find_one({
        "_id": ObjectId(payload.transaction_id),
        "user_id": user_id,
        "status": "flagged",
    })
    
    if not txn:
        raise HTTPException(status_code=404, detail="Flagged transaction not found")
    
    # Count existing OTPs for this transaction
    otp_count = await db.otps.count_documents({
        "user_id": user_id,
        "purpose": "transaction_approval",
        "metadata.transaction_id": payload.transaction_id
    })
    
    if otp_count >= 3:
        # Lock account for 3 hours
        lock_until = datetime.utcnow() + timedelta(hours=3)
        await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"locked_until": lock_until}}
        )
        
        # ✅ SAVE TO ANOMALY_LOGS
        txn["status"] = "blocked"
        txn["anomaly_reason"] = "Excessive OTP requests"
        await handle_anomaly(
            {
                "is_anomaly": True,
                "event_type": "transaction",
                "event_data": txn,
            },
            db,
        )
        
        # Send email notification
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        reason_summary = "excessive OTP requests for a flagged transaction"
        email_subject = "Account Temporarily Locked"
        email_body = f"""
Dear {user.get('first_name', 'User')},

Your account has been temporarily locked for 3 hours due to {reason_summary}.

If this wasn't you, please contact support immediately.

Regards,
Your Security Team
        """
        asyncio.create_task(send_email(email, email_subject, email_body))
        
        raise HTTPException(status_code=429, detail="Maximum OTP attempts reached. Account locked for 3 hours.")
    
    await create_or_resend_otp(
        db=db,
        user_id=user_id,
        email=email,
        purpose="transaction_approval",
        metadata={"transaction_id": payload.transaction_id},
    )
    
    return {"message": "OTP has been sent to your email"}

# --------------------------------------------------
# VERIFY OTP
# --------------------------------------------------
@router.post("/verify-otp")
async def verify_transaction_otp(
    payload: VerifyOTPRequest,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    user_id = current_user["id"]
    
    await verify_otp(
        db=db,
        user_id=user_id,
        purpose="transaction_approval",
        otp=payload.otp,
        metadata={"transaction_id": payload.transaction_id}
    )
    
    flagged = await db.flagged_transactions.find_one({
        "_id": ObjectId(payload.transaction_id),
        "user_id": user_id,
        "status": "flagged",
    })
    
    if not flagged:
        raise HTTPException(status_code=404, detail="Flagged transaction not found")
    
    flagged["status"] = "resolved"
    flagged["approved_at"] = datetime.utcnow()
    
    result = await db.transactions.insert_one(flagged)
    inserted_id = str(result.inserted_id)
    
    await db.flagged_transactions.delete_one({"_id": ObjectId(payload.transaction_id)})
    
    flagged["_id"] = inserted_id
    push_recent_txn(user_id, flagged)
    
    return {"message": "Transaction resolved successfully", "data": flagged}

# --------------------------------------------------
# GET TRANSACTIONS
# --------------------------------------------------
@router.get("")
async def get_transactions(
    db=Depends(get_database),
    current_user=Depends(get_current_user),
    from_dt: Optional[str] = None,
    to_dt: Optional[str] = None,
    min_amount: Optional[float] = None,
    max_amount: Optional[float] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    sort_by: str = "transaction_date",
    desc: bool = True,
):
    user_id = current_user["id"]
    base_query = {"user_id": user_id}
    
    date_filter = {}
    if from_dt:
        date_filter["$gte"] = datetime.fromisoformat(from_dt)
    if to_dt:
        date_filter["$lte"] = datetime.fromisoformat(to_dt)
    if date_filter:
        date_filter = {"transaction_date": date_filter}
    
    amount_filter = {}
    if min_amount is not None:
        amount_filter["$gte"] = min_amount
    if max_amount is not None:
        amount_filter["$lte"] = max_amount
    if amount_filter:
        amount_filter = {"amount": amount_filter}
    
    cat_filter = {"category": category} if category else {}
    status_filter = {"status": status} if status else {}
    
    # Fetch from transactions (completed, resolved)
    txn_query = {**base_query, **date_filter, **amount_filter, **cat_filter, **status_filter}
    completed_resolved = await db.transactions.find(txn_query).to_list(1000)
    
    # Fetch from flagged_transactions (flagged)
    flagged_list = []
    flagged_query = {**base_query, **date_filter, **amount_filter, **cat_filter}
    if not status or status == "flagged":
        flagged_list = await db.flagged_transactions.find(flagged_query).to_list(1000)
    
    # Fetch from anomaly_logs (blocked) - with proper filtering
    blocked_list = []
    anomaly_query = {
        **base_query,
        "anomaly_type": "transaction",
        "status": "blocked"
    }
    
    # Apply date filter for anomaly_logs (they use 'detected_at' instead of 'transaction_date')
    if from_dt or to_dt:
        anomaly_date_filter = {}
        if from_dt:
            anomaly_date_filter["$gte"] = datetime.fromisoformat(from_dt)
        if to_dt:
            anomaly_date_filter["$lte"] = datetime.fromisoformat(to_dt)
        anomaly_query["detected_at"] = anomaly_date_filter
    
    if amount_filter:
        anomaly_query.update(amount_filter)
    if cat_filter:
        anomaly_query.update(cat_filter)
    
    if not status or status == "blocked":
        blocked_list = await db.anomaly_logs.find(anomaly_query).to_list(1000)
    
    all_txns = completed_resolved + flagged_list + blocked_list
    
    # Sort the combined list
    if sort_by == "transaction_date":
        all_txns.sort(
            key=lambda x: x.get("transaction_date") or x.get("detected_at") or datetime.min, 
            reverse=desc
        )
    elif sort_by == "amount":
        all_txns.sort(key=lambda x: x.get("amount", 0), reverse=desc)
    elif sort_by == "status":
        all_txns.sort(key=lambda x: x.get("status", ""), reverse=desc)
    
    # Serialize dates
    for txn in all_txns:
        txn["_id"] = str(txn["_id"])
        if isinstance(txn.get("transaction_date"), datetime):
            txn["transaction_date"] = txn["transaction_date"].isoformat()
        if isinstance(txn.get("previous_transaction_date"), datetime):
            txn["previous_transaction_date"] = txn["previous_transaction_date"].isoformat() if txn.get("previous_transaction_date") else None
        if isinstance(txn.get("approved_at"), datetime):
            txn["approved_at"] = txn["approved_at"].isoformat() if txn.get("approved_at") else None
        if isinstance(txn.get("detected_at"), datetime):
            txn["detected_at"] = txn["detected_at"].isoformat()
    
    return {
        "transactions": all_txns,
        "count": len(all_txns),
    }