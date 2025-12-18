# app/api/v1/routes/auth_route.py

from fastapi import APIRouter, HTTPException, Depends, Request
from app.schemas.user_schema import UserSignup, UserLogin, TokenResponse
from app.core.security import hash_password, verify_password, create_access_token
from app.db.mongodb import get_database
from datetime import datetime, timedelta
from bson import ObjectId

# Redis utilities
from app.core.dsa.redis_dsa import (
    record_login_attempt,
    set_last_ip,
    set_last_device,
    push_recent_login,
)

# Login model
from app.db.models.login_log_model import LoginLogModel

# Hybrid anomaly detection
from app.hybrid_model.hybrid_login import hybrid_login_decision
from app.utils.login_feature_extractor import extract_login_features

# utils
from app.utils.device_utils import parse_device_info
from app.utils.ip_utils import get_client_ip
from app.utils.ip_utils import get_geolocation

router = APIRouter(tags=["Authentication"])


# ===========================
#           SIGNUP
# ===========================
@router.post("/signup")
async def signup(user: UserSignup, db=Depends(get_database)):
    existing_user = await db["users"].find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = user.model_dump(by_alias=False)
    new_user["password"] = hash_password(user.password)
    new_user["created_at"] = datetime.utcnow()
    new_user["status"] = "active"

    result = await db["users"].insert_one(new_user)

    return {
        "status": "success",
        "message": "Account created successfully",
        "user_id": str(result.inserted_id)
    }


# ===========================
#            LOGIN
# ===========================
@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, request: Request, db=Depends(get_database)):

    # 1️⃣ Fetch user
    user = await db["users"].find_one({"email": credentials.email})

    # LOGIN FAILED → invalid email
    if not user:
        await _create_login_log(
            db=db,
            email=credentials.email,
            user_id=None,
            request=request,
            device_data=getattr(credentials, "device_data", None),
            status="failed"
        )
        raise HTTPException(status_code=400, detail="Invalid email or password")

    # LOGIN FAILED → wrong password
    if not verify_password(credentials.password, user["password"]):
        await _create_login_log(
            db=db,
            email=user["email"],
            user_id=str(user["_id"]),
            request=request,
            device_data=getattr(credentials, "device_data", None),
            status="failed"
        )
        raise HTTPException(status_code=400, detail="Invalid email or password")

    # 2️⃣ LOGIN SUCCESS → create log
    await _create_login_log(
        db=db,
        email=user["email"],
        user_id=str(user["_id"]),
        request=request,
        device_data=getattr(credentials, "device_data", None),
        status="success"
    )

    # 3️⃣ Generate access token
    token = create_access_token({
        "id": str(user["_id"]),
        "email": user["email"]
    })

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        requires_2fa=False,  # Phase-2 feature
        risk_score=0         # Phase-2 feature
    )


# ===========================
#  HELPER: CREATE LOGIN LOG
# ===========================
async def _create_login_log(
    db,
    email: str,
    user_id: str | None,
    request: Request,
    device_data: dict | None,
    status: str = "success"
) -> str:

    ip_address = get_client_ip(request)
    location = await get_geolocation(ip_address)

    device_info = parse_device_info(device_data or {})
    device_id = device_info["device_id"]

    # Fetch previous successful login (for feature extraction)
    previous_login_time = None
    previous_login_doc: dict | None = None

    if user_id:
        previous = await db.login_logs.find_one(
            {"user_id": user_id, "status": "success"},
            sort=[("login_time", -1)]
        )
        if previous:
            previous_login_time = previous["login_time"]
            # Keep full previous doc for device/IP/location comparison
            previous_login_doc = previous

    # ✅ FIXED: Count recent failed attempts instead of total logins
    login_attempts = 1  # Default for first attempt
    if user_id:
        # Count failed attempts in the last 15 minutes
        recent_window = datetime.utcnow() - timedelta(minutes=15)
        recent_failed = await db.login_logs.count_documents({
            "user_id": user_id,
            "status": "failed",
            "login_time": {"$gte": recent_window}
        })
        # Current attempt = recent failed attempts + 1
        login_attempts = recent_failed + 1

    # Construct base log entry (without hybrid fields yet)
    login_log = {
        "user_id": user_id,
        "email": email,
        "device_id": device_id,
        "device_info": device_info,
        "ip_address": ip_address,
        "location": location,
        "login_time": datetime.utcnow(),
        "previous_login_time": previous_login_time,
        "login_attempts": login_attempts,  # ✅ Now correctly counts recent failed attempts
        "status": status,              # success / failed / blocked
        # Hybrid fields will be filled after running the detector
    }

    # -------------------------------------------------
    # HYBRID LOGIN ANOMALY DETECTION
    # -------------------------------------------------
    try:
        # Build feature dataframe for current login
        features_df = extract_login_features(
            current_login={
                "login_time": login_log["login_time"],
                "device_id": login_log["device_id"],
                "ip_address": login_log["ip_address"],
                "location": login_log["location"],
                "login_attempts": login_log["login_attempts"],
            },
            previous_login=previous_login_doc,
            login_status=status,
        )

        hybrid_result = hybrid_login_decision(features_df)

        # Map hybrid outputs onto log document
        login_log["rule_flag"] = hybrid_result.get("rule_flag")
        login_log["rule_score"] = hybrid_result.get("rule_score")
        login_log["ml_score"] = hybrid_result.get("ml_score")
        login_log["hybrid_score"] = hybrid_result.get("hybrid_score")
        login_log["is_moderate"] = hybrid_result.get("is_moderate")
        login_log["is_anomaly"] = bool(hybrid_result.get("is_anomaly", 0))

        # Optional: map hybrid_score (0–1) to 0–100 risk_score for UI
        hybrid_score = hybrid_result.get("hybrid_score")
        if hybrid_score is not None:
            login_log["risk_score"] = int(round(float(hybrid_score) * 100))
        else:
            login_log["risk_score"] = 0

    except Exception:
        # Fail-safe: if detection fails, still log the event without blocking login.
        # Ensure ALL hybrid-related fields exist so downstream consumers and
        # integration tests always see a complete shape.
        login_log.setdefault("rule_flag", 0)
        login_log.setdefault("rule_score", 0.0)
        login_log.setdefault("ml_score", 0.0)
        login_log.setdefault("hybrid_score", 0.0)
        login_log.setdefault("is_moderate", 0)
        login_log.setdefault("is_anomaly", False)
        login_log.setdefault("risk_score", 0)

    # Save in Mongo
    log_result = await db.login_logs.insert_one(login_log)

    # Store in Redis (with automatic datetime cleaning)
    redis_log = {
        **login_log,
        "_id": str(log_result.inserted_id)
    }
    
    push_recent_login(user_id or "unknown", redis_log)
    
    return str(log_result.inserted_id)