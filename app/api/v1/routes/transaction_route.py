"""
UPDATED transaction_route.py - Key Changes Only
------------------------------------------------
Full file is too long, showing critical updates
"""

"""
Complete Updated Transaction Route
-----------------------------------
backend/app/api/v1/routes/transaction_route.py

Updates:
- Added user statistics calculation
- Fixed feature engineering
- Better severity handling
- Improved error messages
- Enhanced email notifications
"""

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
# HELPER: Get User Statistics
# --------------------------------------------------
async def get_user_statistics(db, user_id: str) -> dict:
    """
    Calculate user's historical transaction statistics
    Used for dynamic rule-based scoring
    
    Returns:
        dict: {avg_amount, max_amount, min_amount, transaction_count}
    """
    try:
        pipeline = [
            {
                "$match": {
                    "user_id": user_id,
                    "status": {"$in": ["completed", "resolved"]}
                }
            },
            {
                "$group": {
                    "_id": None,
                    "avg_amount": {"$avg": "$amount"},
                    "max_amount": {"$max": "$amount"},
                    "min_amount": {"$min": "$amount"},
                    "transaction_count": {"$sum": 1},
                    "total_volume": {"$sum": "$amount"}
                }
            }
        ]
        
        result = await db.transactions.aggregate(pipeline).to_list(1)
        
        if result and result[0]["transaction_count"] > 0:
            stats = result[0]
            return {
                "avg_amount": float(stats.get("avg_amount", 100.0)),
                "max_amount": float(stats.get("max_amount", 1000.0)),
                "min_amount": float(stats.get("min_amount", 10.0)),
                "transaction_count": int(stats.get("transaction_count", 0)),
                "total_volume": float(stats.get("total_volume", 0.0))
            }
        else:
            # No history - return defaults
            return {
                "avg_amount": 100.0,
                "max_amount": 1000.0,
                "min_amount": 10.0,
                "transaction_count": 0,
                "total_volume": 0.0
            }
    
    except Exception as e:
        print(f"⚠️  Error calculating user stats: {e}")
        return {
            "avg_amount": 100.0,
            "max_amount": 1000.0,
            "min_amount": 10.0,
            "transaction_count": 0,
            "total_volume": 0.0
        }

# --------------------------------------------------
# FEATURE ENGINEERING
# --------------------------------------------------
async def calculate_transaction_features(
    db, user_id: str, current_txn: dict, last_txn: dict = None
):
    """
    Calculate all features needed for ML models
    
    Args:
        db: Database connection
        user_id: User ID
        current_txn: Current transaction data
        last_txn: Previous transaction (if exists)
    
    Returns:
        dict: Enhanced transaction with all calculated features
    """
    now = current_txn["transaction_date"]
    amount = current_txn["amount"]
    
    # Time-based features
    hour = now.hour
    day_of_week = now.weekday()
    day = now.day
    
    # Calculate recent transaction counts
    one_hour_ago = now - timedelta(hours=1)
    twenty_four_hours_ago = now - timedelta(hours=24)
    
    try:
        tx_last_1hr = await db.transactions.count_documents({
            "user_id": user_id,
            "transaction_date": {"$gte": one_hour_ago, "$lt": now},
            "status": {"$in": ["completed", "resolved"]}
        })
        
        tx_last_24hr = await db.transactions.count_documents({
            "user_id": user_id,
            "transaction_date": {"$gte": twenty_four_hours_ago, "$lt": now},
            "status": {"$in": ["completed", "resolved"]}
        })
    except Exception as e:
        print(f"⚠️  Error counting recent transactions: {e}")
        tx_last_1hr = 0
        tx_last_24hr = 0
    
    # Get user's transaction history for amount statistics
    try:
        user_txns = await db.transactions.find(
            {
                "user_id": user_id,
                "status": {"$in": ["completed", "resolved"]}
            },
            {"amount": 1, "category": 1}
        ).to_list(length=1000)
    except Exception as e:
        print(f"⚠️  Error fetching user transactions: {e}")
        user_txns = []
    
    # Calculate amount-based features
    if user_txns and len(user_txns) > 0:
        amounts = [float(t.get("amount", 0)) for t in user_txns]
        mean_amount = np.mean(amounts)
        std_amount = np.std(amounts) if len(amounts) > 1 else max(mean_amount * 0.3, 1.0)
        
        # Z-score: how many standard deviations from mean
        if std_amount > 0:
            amount_zscore = (amount - mean_amount) / std_amount
        else:
            amount_zscore = 0.0
        
        # Category-specific statistics
        category = current_txn.get("category", "")
        cat_amounts = [float(t.get("amount", 0)) for t in user_txns if t.get("category") == category]
        
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
        # First transaction or no history
        amount_zscore = 0.0
        category_amount_zscore = 0.0
        category_usage_ratio = 0.0
        new_category_flag = 1
        unique_category_count = 1
    
    # Get user profile
    try:
        user_profile = await db.users.find_one({"_id": ObjectId(user_id)})
        if user_profile:
            account_balance = float(user_profile.get("account_balance", 10000.0))
            customer_age = int(user_profile.get("age", 30))
        else:
            account_balance = 10000.0
            customer_age = 30
    except Exception as e:
        print(f"⚠️  Error fetching user profile: {e}")
        account_balance = 10000.0
        customer_age = 30
    
    # Calculate amount to balance ratio (with safety check)
    amount_to_balance = amount / account_balance if account_balance > 0 else 0.0
    
    # High-risk category detection
    HIGH_RISK_CATEGORIES = ["Gambling", "Cryptocurrency", "International", "Cash Withdrawal"]
    high_risk_category = 1 if current_txn.get("category", "") in HIGH_RISK_CATEGORIES else 0
    
    # Device/IP/Location change detection
    device_changed = 0
    ip_changed = 0
    location_changed = 0
    
    if last_txn:
        # Device change
        curr_device = current_txn.get("device_id")
        last_device = last_txn.get("device_id")
        device_changed = 1 if curr_device and last_device and curr_device != last_device else 0
        
        # IP change
        curr_ip = current_txn.get("ip")
        last_ip = last_txn.get("ip")
        ip_changed = 1 if curr_ip and last_ip and curr_ip != last_ip else 0
        
        # Location change
        curr_city = current_txn.get("location", {}).get("city")
        last_city = last_txn.get("location", {}).get("city")
        location_changed = 1 if curr_city and last_city and curr_city != last_city else 0
    
    # Login attempts (default to 0 for now)
    login_attempts = 0
    
    # Build enhanced transaction with all features
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
        "customer_age": customer_age,
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
    """
    Create a new transaction with hybrid anomaly detection
    
    Flow:
    1. Check if account is locked
    2. Get request metadata (IP, device, location)
    3. Calculate transaction features
    4. Run hybrid detection (rule + ML)
    5. Make decision based on severity:
       - normal/low: approve immediately
       - moderate: flag for OTP verification
       - high/critical: block and lock account
    """
    user_id = current_user["id"]
    email = current_user["email"]
    
    # --------------------------------------------------
    # 1. Check Account Lock Status
    # --------------------------------------------------
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    locked_until = user.get("locked_until")
    if locked_until and locked_until > datetime.utcnow():
        time_remaining = (locked_until - datetime.utcnow()).total_seconds() / 60
        raise HTTPException(
            status_code=403,
            detail=f"Account locked for {int(time_remaining)} more minutes due to security reasons. Please try again at {locked_until.strftime('%H:%M:%S')}."
        )
    
    # --------------------------------------------------
    # 2. Get Request Metadata
    # --------------------------------------------------
    ip_address = get_client_ip(request)
    device_id = get_device_id(request)
    location = get_location_from_ip(ip_address)
    
    # --------------------------------------------------
    # 3. Get Last Transaction
    # --------------------------------------------------
    try:
        last_txn = await db.transactions.find_one(
            {"user_id": user_id},
            sort=[("transaction_date", -1)]
        )
    except Exception as e:
        print(f"⚠️  Error fetching last transaction: {e}")
        last_txn = None
    
    # Calculate time since last transaction
    prev_date = last_txn.get("transaction_date") if last_txn else None
    now = datetime.utcnow()
    transaction_duration = None
    
    if prev_date and isinstance(prev_date, datetime):
        transaction_duration = (now - prev_date).total_seconds()
    
    # Generate merchant ID
    merchant_id = f"MCT-{data.category[:3].upper()}-{user_id[:4]}"
    
    # --------------------------------------------------
    # 4. Build Current Transaction
    # --------------------------------------------------
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
    
    # --------------------------------------------------
    # 5. Calculate Features
    # --------------------------------------------------
    try:
        enhanced_txn = await calculate_transaction_features(
            db, user_id, current_txn, last_txn
        )
    except Exception as e:
        print(f"❌ Error calculating features: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error processing transaction. Please try again."
        )
    
    # --------------------------------------------------
    # 6. Get User Statistics
    # --------------------------------------------------
    try:
        user_stats = await get_user_statistics(db, user_id)
    except Exception as e:
        print(f"⚠️  Error getting user stats: {e}")
        user_stats = None
    
    # --------------------------------------------------
    # 7. Run Hybrid Detection
    # --------------------------------------------------
    try:
        hybrid = hybrid_transaction_decision(enhanced_txn, last_txn, user_stats)
    except Exception as e:
        print(f"❌ Error in hybrid detection: {e}")
        # Fallback to safe decision
        hybrid = {
            "rule_flag": 1,
            "rule_score": 0.5,
            "rule_raw_score": 50,
            "rule_details": {},
            "ml_iso_score": 0.5,
            "ml_ae_score": 0.5,
            "ml_score": 0.5,
            "hybrid_score": 0.5,
            "is_moderate": 1,
            "is_anomaly": 0,
            "severity": "moderate",
            "reasons": [{"message": "Error in detection system, flagging for manual review"}],
            "reason_summary": "System error - manual review required"
        }
    
    # --------------------------------------------------
    # 8. Build Transaction Document
    # --------------------------------------------------
    txn_dict = {
        **enhanced_txn,
        "merchant_id": merchant_id,
        "rule_flag": int(hybrid.get("rule_flag", 0)),
        "rule_score": float(hybrid.get("rule_score", 0.0)),
        "rule_raw_score": int(hybrid.get("rule_raw_score", 0)),
        "rule_details": hybrid.get("rule_details", {}),
        "ml_iso_score": float(hybrid.get("ml_iso_score", 0.0)),
        "ml_ae_score": float(hybrid.get("ml_ae_score", 0.0)),
        "ml_score": float(hybrid.get("ml_score", 0.0)),
        "hybrid_score": float(hybrid.get("hybrid_score", 0.0)),
        "is_moderate": int(hybrid.get("is_moderate", 0)),
        "is_anomaly": bool(hybrid.get("is_anomaly", False)),
        "severity": hybrid.get("severity", "normal"),
        "reasons": hybrid.get("reasons", []),
        "reason_summary": hybrid.get("reason_summary", "No issues detected"),
        "risk_score": int(round(float(hybrid.get("hybrid_score", 0.0)) * 100)),
    }
    
    # --------------------------------------------------
    # 9. Make Decision Based on Severity
    # --------------------------------------------------
    severity = hybrid.get("severity", "normal")
    
    # ✅ CASE 1: Normal or Low Risk - Approve Immediately
    if severity in ["normal", "low"]:
        txn_dict["status"] = "completed"
        
        try:
            result = await db.transactions.insert_one(txn_dict)
            txn_dict["_id"] = str(result.inserted_id)
            
            # Push to Redis for recent transactions
            try:
                push_recent_txn(user_id, txn_dict)
            except Exception as e:
                print(f"⚠️  Redis push failed: {e}")
            
            # Serialize datetime for response
            txn_dict["transaction_date"] = txn_dict["transaction_date"].isoformat()
            if txn_dict.get("previous_transaction_date"):
                txn_dict["previous_transaction_date"] = txn_dict["previous_transaction_date"].isoformat()
            
            return {
                "message": "Transaction completed successfully",
                "data": txn_dict,
                "severity": severity,
                "risk_score": txn_dict["risk_score"]
            }
        
        except Exception as e:
            print(f"❌ Error saving transaction: {e}")
            raise HTTPException(
                status_code=500,
                detail="Error processing transaction. Please try again."
            )
    
    # ⚠️ CASE 2: Moderate Risk - Flag for OTP Verification
    elif severity == "moderate":
        txn_dict["status"] = "flagged"
        
        try:
            result = await db.flagged_transactions.insert_one(txn_dict)
            txn_dict["_id"] = str(result.inserted_id)
            
            # Push to Redis
            try:
                push_recent_txn(user_id, txn_dict)
            except Exception as e:
                print(f"⚠️  Redis push failed: {e}")
            
            # Serialize datetime
            txn_dict["transaction_date"] = txn_dict["transaction_date"].isoformat()
            if txn_dict.get("previous_transaction_date"):
                txn_dict["previous_transaction_date"] = txn_dict["previous_transaction_date"].isoformat()
            
            return {
                "message": "Transaction flagged for verification. Please click 'Request OTP' to receive a verification code on your email.",
                "data": txn_dict,
                "severity": severity,
                "risk_score": txn_dict["risk_score"],
                "action_required": "otp_verification"
            }
        
        except Exception as e:
            print(f"❌ Error saving flagged transaction: {e}")
            raise HTTPException(
                status_code=500,
                detail="Error processing transaction. Please try again."
            )
    
    # 🚨 CASE 3: High or Critical Risk - Block Transaction
    else:  # severity in ["high", "critical"]
        txn_dict["status"] = "blocked"
        
        try:
            # Save to anomaly logs
            txn_id = await handle_anomaly(
                {
                    "is_anomaly": True,
                    "event_type": "transaction",
                    "event_data": txn_dict,
                },
                db,
            )
            txn_dict["_id"] = txn_id
            
            # Push to Redis
            try:
                push_recent_txn(user_id, txn_dict)
            except Exception as e:
                print(f"⚠️  Redis push failed: {e}")
            
            # Get reason from anomaly log
            try:
                anomaly_log = await db.anomaly_logs.find_one({"_id": ObjectId(txn_id)})
                reason_summary = anomaly_log.get("reason_summary") if anomaly_log else "suspicious activity detected"
            except Exception:
                reason_summary = "suspicious activity detected"
            
            # Lock account for 3 hours
            lock_duration_hours = 3
            lock_until = datetime.utcnow() + timedelta(hours=lock_duration_hours)
            
            await db.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"locked_until": lock_until}}
            )
            
            # Send email notification
            email_subject = "🔒 Security Alert - Account Temporarily Locked"
            email_body = f"""
Dear {user.get('first_name', 'User')},

Your account has been temporarily locked for {lock_duration_hours} hours due to {reason_summary}.

⚠️ Transaction Details:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Amount:      ${txn_dict['amount']:.2f}
Category:    {txn_dict['category']}
Description: {txn_dict['description']}
Time:        {txn_dict['transaction_date'].strftime('%Y-%m-%d %H:%M:%S')}
Location:    {location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}
Risk Score:  {txn_dict['risk_score']}/100 ({severity.upper()})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔓 Your account will be automatically unlocked at:
   {lock_until.strftime('%Y-%m-%d %H:%M:%S')}

⚠️ If you did NOT make this transaction:
   Please contact our security team immediately at:
   📧 security@yourbank.com
   📞 1-800-SECURITY

For your safety, do not share your account credentials with anyone.

Best regards,
Your Security Team
            """
            
            # Send email asynchronously
            asyncio.create_task(send_email(email, email_subject, email_body))
            
            # Serialize datetime
            txn_dict["transaction_date"] = txn_dict["transaction_date"].isoformat()
            if txn_dict.get("previous_transaction_date"):
                txn_dict["previous_transaction_date"] = txn_dict["previous_transaction_date"].isoformat()
            
            return {
                "message": f"Transaction blocked due to {severity} security risk. Your account has been locked for {lock_duration_hours} hours.",
                "data": txn_dict,
                "severity": severity,
                "risk_score": txn_dict["risk_score"],
                "locked_until": lock_until.isoformat(),
                "reason": reason_summary
            }
        
        except Exception as e:
            print(f"❌ Error handling blocked transaction: {e}")
            raise HTTPException(
                status_code=500,
                detail="Transaction blocked. Please contact support."
            )

# --------------------------------------------------
# REQUEST OTP (Manual Send + Resend)
# --------------------------------------------------
@router.post("/request-otp")
async def request_transaction_otp(
    payload: RequestOTPRequest,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    """
    Request OTP for a flagged transaction
    Can be called multiple times to resend OTP
    After 3 attempts, account is locked
    """
    user_id = current_user["id"]
    email = current_user["email"]
    
    # Check if transaction exists and is flagged
    try:
        txn = await db.flagged_transactions.find_one({
            "_id": ObjectId(payload.transaction_id),
            "user_id": user_id,
            "status": "flagged",
        })
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid transaction ID")
    
    if not txn:
        raise HTTPException(
            status_code=404,
            detail="Flagged transaction not found or already processed"
        )
    
    # Count existing OTP requests for this transaction
    try:
        otp_count = await db.otps.count_documents({
            "user_id": user_id,
            "purpose": "transaction_approval",
            "metadata.transaction_id": payload.transaction_id
        })
    except Exception as e:
        print(f"⚠️  Error counting OTPs: {e}")
        otp_count = 0
    
    # Max 3 OTP attempts
    if otp_count >= 3:
        # Lock account for 3 hours
        lock_until = datetime.utcnow() + timedelta(hours=3)
        await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"locked_until": lock_until}}
        )
        
        # Move to blocked
        txn["status"] = "blocked"
        txn["anomaly_reason"] = "Excessive OTP requests"
        
        # Save to anomaly logs
        await handle_anomaly(
            {
                "is_anomaly": True,
                "event_type": "transaction",
                "event_data": txn,
            },
            db,
        )
        
        # Delete from flagged
        await db.flagged_transactions.delete_one({"_id": ObjectId(payload.transaction_id)})
        
        # Send email notification
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        email_subject = "🔒 Account Locked - Excessive OTP Requests"
        email_body = f"""
Dear {user.get('first_name', 'User')},

Your account has been temporarily locked for 3 hours due to excessive OTP verification attempts for a flagged transaction.

If you did not make these requests, please contact support immediately at security@yourbank.com.

Your account will be unlocked at {lock_until.strftime('%Y-%m-%d %H:%M:%S')}.

Regards,
Your Security Team
        """
        asyncio.create_task(send_email(email, email_subject, email_body))
        
        raise HTTPException(
            status_code=429,
            detail="Maximum OTP attempts reached. Account locked for 3 hours."
        )
    
    # Create/resend OTP
    try:
        await create_or_resend_otp(
            db=db,
            user_id=user_id,
            email=email,
            purpose="transaction_approval",
            metadata={"transaction_id": payload.transaction_id},
        )
        
        return {
            "message": f"OTP has been sent to {email}",
            "attempts_remaining": 3 - otp_count - 1
        }
    
    except Exception as e:
        print(f"❌ Error sending OTP: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error sending OTP. Please try again."
        )

# --------------------------------------------------
# VERIFY OTP
# --------------------------------------------------
@router.post("/verify-otp")
async def verify_transaction_otp(
    payload: VerifyOTPRequest,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    """
    Verify OTP and approve flagged transaction
    """
    user_id = current_user["id"]
    
    # Verify OTP
    try:
        await verify_otp(
            db=db,
            user_id=user_id,
            purpose="transaction_approval",
            otp=payload.otp,
            metadata={"transaction_id": payload.transaction_id}
        )
    except HTTPException as e:
        # Re-raise HTTP exceptions from verify_otp
        raise e
    except Exception as e:
        print(f"❌ Error verifying OTP: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error verifying OTP. Please try again."
        )
    
    # Get flagged transaction
    try:
        flagged = await db.flagged_transactions.find_one({
            "_id": ObjectId(payload.transaction_id),
            "user_id": user_id,
            "status": "flagged",
        })
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid transaction ID")
    
    if not flagged:
        raise HTTPException(
            status_code=404,
            detail="Flagged transaction not found or already processed"
        )
    
    # Update status and move to transactions collection
    flagged["status"] = "resolved"
    flagged["approved_at"] = datetime.utcnow()
    flagged["approved_via"] = "otp_verification"
    
    try:
        # Insert into transactions
        result = await db.transactions.insert_one(flagged)
        inserted_id = str(result.inserted_id)
        
        # Delete from flagged
        await db.flagged_transactions.delete_one({"_id": ObjectId(payload.transaction_id)})
        
        # Update response
        flagged["_id"] = inserted_id
        
        # Push to Redis
        try:
            push_recent_txn(user_id, flagged)
        except Exception as e:
            print(f"⚠️  Redis push failed: {e}")
        
        # Serialize datetime
        if isinstance(flagged.get("transaction_date"), datetime):
            flagged["transaction_date"] = flagged["transaction_date"].isoformat()
        if isinstance(flagged.get("previous_transaction_date"), datetime):
            flagged["previous_transaction_date"] = flagged["previous_transaction_date"].isoformat()
        if isinstance(flagged.get("approved_at"), datetime):
            flagged["approved_at"] = flagged["approved_at"].isoformat()
        
        return {
            "message": "Transaction verified and approved successfully",
            "data": flagged
        }
    
    except Exception as e:
        print(f"❌ Error approving transaction: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error approving transaction. Please contact support."
        )

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