from fastapi import APIRouter, Depends, Request
from datetime import datetime, timedelta
from app.db.mongodb import get_database
from app.schemas.transaction_schema import TransactionCreate
from app.db.models.transaction_model import TransactionModel
from app.utils.geoip_utils import get_location_from_ip
from app.utils.ip_utils import get_client_ip
from app.utils.device_utils import get_device_id
from app.api.v1.routes.anomaly_route import handle_anomaly
from app.core.dsa.redis_dsa import push_recent_txn
from app.core.security import get_current_user
from typing import Optional
import numpy as np

from app.hybrid_model.hybrid_transaction import hybrid_transaction_decision

router = APIRouter(prefix="/transactions", tags=["Transactions"])


async def calculate_transaction_features(
    db, user_id: str, current_txn: dict, last_txn: dict = None
):
    """
    Calculate advanced features required by ML models.
    """
    now = current_txn["transaction_date"]
    amount = current_txn["amount"]
    
    # Time-based features
    hour = now.hour
    day_of_week = now.weekday()
    day = now.day
    
    # Transaction frequency (last 1hr and 24hr)
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
    
    # Amount statistics
    user_txns = await db.transactions.find(
        {"user_id": user_id},
        {"amount": 1, "category": 1}
    ).to_list(length=1000)
    
    if user_txns:
        amounts = [t["amount"] for t in user_txns]
        mean_amount = np.mean(amounts)
        std_amount = np.std(amounts) if len(amounts) > 1 else 1.0
        
        # Z-score for overall amount
        amount_zscore = (amount - mean_amount) / std_amount if std_amount > 0 else 0.0
        
        # Category-specific statistics
        category = current_txn["category"]
        cat_amounts = [t["amount"] for t in user_txns if t.get("category") == category]
        
        if cat_amounts:
            cat_mean = np.mean(cat_amounts)
            cat_std = np.std(cat_amounts) if len(cat_amounts) > 1 else 1.0
            category_amount_zscore = (amount - cat_mean) / cat_std if cat_std > 0 else 0.0
            
            # Category usage ratio
            category_usage_ratio = len(cat_amounts) / len(amounts)
            new_category_flag = 0
        else:
            category_amount_zscore = 0.0
            category_usage_ratio = 0.0
            new_category_flag = 1
        
        # Unique categories count
        unique_categories = len(set(t.get("category") for t in user_txns if t.get("category")))
        unique_category_count = unique_categories
    else:
        # First transaction defaults
        amount_zscore = 0.0
        category_amount_zscore = 0.0
        category_usage_ratio = 0.0
        new_category_flag = 1
        unique_category_count = 1
    
    # Account balance (fetch from user profile or set default)
    user_profile = await db.users.find_one({"_id": user_id})
    account_balance = user_profile.get("account_balance", 10000.0) if user_profile else 10000.0
    
    # Amount to balance ratio
    amount_to_balance = amount / account_balance if account_balance > 0 else 0.0
    
    # High-risk categories
    HIGH_RISK_CATEGORIES = ["Gambling", "Cryptocurrency", "International", "Cash Withdrawal"]
    high_risk_category = 1 if current_txn["category"] in HIGH_RISK_CATEGORIES else 0
    
    # Device/IP/Location changes
    device_changed = 0
    ip_changed = 0
    location_changed = 0
    
    if last_txn:
        device_changed = 1 if current_txn.get("device_id") != last_txn.get("device_id") else 0
        ip_changed = 1 if current_txn.get("ip") != last_txn.get("ip") else 0
        
        curr_city = current_txn.get("location", {}).get("city")
        last_city = last_txn.get("location", {}).get("city")
        location_changed = 1 if curr_city and last_city and curr_city != last_city else 0
    
    # Login attempts (fetch from auth logs or set default)
    login_attempts = 0  # Should be fetched from authentication service
    
    # Build enhanced transaction dict
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


@router.post("")
async def create_transaction(
    request: Request,
    data: TransactionCreate,
    db=Depends(get_database),
    current_user=Depends(get_current_user)
):
    user_id = current_user["id"]

    ip_address = get_client_ip(request)
    device_id = get_device_id(request)
    location = get_location_from_ip(ip_address)

    # Fetch last transaction
    last_txn = await db.transactions.find_one(
        {"user_id": user_id}, sort=[("_id", -1)]
    )

    previous_txn_date = None
    if last_txn:
        prev = last_txn.get("transaction_date")
        previous_txn_date = datetime.fromisoformat(prev) if isinstance(prev, str) else prev

    now = datetime.utcnow()

    transaction_duration = (
        (now - previous_txn_date).total_seconds() if previous_txn_date else None
    )

    merchant_id = f"MCT-{data.category[:3].upper()}-{user_id[:4]}"

    # Build basic transaction dict
    current_txn = {
        "user_id": user_id,
        "amount": data.amount,
        "category": data.category,
        "ip": ip_address,
        "device_id": device_id,
        "location": location,
        "transaction_date": now,
        "transaction_duration": transaction_duration,
        "previous_transaction_date": previous_txn_date,
    }

    # Calculate advanced features
    enhanced_txn = await calculate_transaction_features(
        db, user_id, current_txn, last_txn
    )

    try:
        # Run hybrid detection with enhanced features
        hybrid_result = hybrid_transaction_decision(enhanced_txn, last_txn)

        rule_flag = int(hybrid_result.get("rule_flag", 0))
        rule_score = float(hybrid_result.get("rule_score", 0.0))
        rule_details = hybrid_result.get("rule_details", {})
        ml_iso_score = float(hybrid_result.get("ml_iso_score", 0.0))
        ml_ae_score = float(hybrid_result.get("ml_ae_score", 0.0))
        ml_score = float(hybrid_result.get("ml_score", 0.0))
        hybrid_score = float(hybrid_result.get("hybrid_score", 0.0))
        is_moderate = int(hybrid_result.get("is_moderate", 0))
        is_anomaly = bool(hybrid_result.get("is_anomaly", 0))
        risk_score = int(round(hybrid_score * 100))
    except Exception as e:
        print(f"Hybrid detection error: {e}")
        # Fail-safe defaults
        rule_flag = 0
        rule_score = 0.0
        rule_details = {}
        ml_iso_score = 0.0
        ml_ae_score = 0.0
        ml_score = 0.0
        hybrid_score = 0.0
        is_moderate = 0
        is_anomaly = False
        risk_score = 0

    # except Exception as e:
    #    import traceback
    #    print("Hybrid detection error:", e)
    #    traceback.print_exc()
    #    raise  # let FastAPI return a 500 so you see the real problem

    # Persist enriched transaction
    txn = TransactionModel(
        user_id=user_id,
        amount=data.amount,
        category=data.category,
        description=data.description,
        ip=ip_address,
        device_id=device_id,
        transaction_date=now,
        location=location,
        merchant_id=merchant_id,
        transaction_duration=transaction_duration,
        previous_transaction_date=previous_txn_date,
        rule_flag=rule_flag,
        rule_score=rule_score,
        rule_details=rule_details,
        ml_iso_score=ml_iso_score,
        ml_ae_score=ml_ae_score,
        ml_score=ml_score,
        hybrid_score=hybrid_score,
        is_moderate=is_moderate,
        is_anomaly=is_anomaly,
        risk_score=risk_score,
    )

    await db.transactions.insert_one(txn.model_dump())

    # Store in Redis
    push_recent_txn(user_id, txn.model_dump())

    # Forward to anomaly handler
    await handle_anomaly(
        {
            "is_anomaly": bool(txn.is_anomaly),
            "event_type": "transaction",
            "event_data": txn.model_dump(),
        },
        db,
    )

    return {"message": "Transaction added", "data": txn.model_dump(mode="json")}


@router.get("")
async def get_user_transactions(
    request: Request,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
    from_dt: Optional[str] = None,
    to_dt: Optional[str] = None,
    sort_by: str = "transaction_date",
    desc: bool = True,
    min_amount: Optional[float] = None,
    max_amount: Optional[float] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
):
    user_id = current_user["id"]
    
    query = {"user_id": user_id}
    
    if from_dt or to_dt:
        query["transaction_date"] = {}
        if from_dt:
            query["transaction_date"]["$gte"] = datetime.fromisoformat(from_dt)
        if to_dt:
            query["transaction_date"]["$lte"] = datetime.fromisoformat(to_dt)
    
    if min_amount is not None or max_amount is not None:
        query["amount"] = {}
        if min_amount is not None:
            query["amount"]["$gte"] = min_amount
        if max_amount is not None:
            query["amount"]["$lte"] = max_amount
    
    if category:
        query["category"] = category
    
    if status:
        query["status"] = status
    
    sort_direction = -1 if desc else 1
    
    cursor = db.transactions.find(query).sort(sort_by, sort_direction)
    transactions = await cursor.to_list(length=1000)
    
    for txn in transactions:
        txn["_id"] = str(txn["_id"])
        if isinstance(txn.get("transaction_date"), datetime):
            txn["transaction_date"] = txn["transaction_date"].isoformat()
    
    return {
        "transactions": transactions,
        "count": len(transactions)
    }

