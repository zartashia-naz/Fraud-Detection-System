from fastapi import APIRouter, HTTPException, Depends, Request
from datetime import datetime, timedelta

from app.schemas.user_schema import UserSignup, UserLogin, TokenResponse
from pydantic import BaseModel

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_temp_token,
    get_current_temp_user
)

from app.db.mongodb import get_database

# Redis
from app.core.dsa.redis_dsa import push_recent_login

# Hybrid anomaly
from app.hybrid_model.hybrid_login import hybrid_login_decision
from app.utils.login_feature_extractor import extract_login_features

# Utils
from app.utils.device_utils import parse_device_info
from app.utils.ip_utils import get_client_ip, get_geolocation

# Trusted devices
from app.services.trusted_device_service import TrustedDeviceService

# OTP
from app.services.otp_service import create_or_resend_otp
from app.services.otp_verify_service import verify_otp

# Email
from app.services.email_service import send_email
import asyncio

from bson import ObjectId
from app.api.v1.routes.anomaly_route import handle_anomaly

# Admin audit logging
from app.services.audit_service import log_admin_action, AuditActions
from app.core.admin_security import get_client_ip as admin_get_client_ip, get_user_agent

router = APIRouter(tags=["Authentication"])

HIGH_RISK_THRESHOLD = 75  # Risk score threshold for blocking account

# ===========================
#           SIGNUP
# ===========================
@router.post("/signup")
async def signup(user: UserSignup, db=Depends(get_database)):
    existing_user = await db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = user.model_dump()
    new_user["password"] = hash_password(user.password)
    new_user["created_at"] = datetime.utcnow()
    new_user["status"] = "active"
    new_user["role"] = "user"  # Always set role to "user" on signup
    new_user["two_factor_enabled"] = False

    # Add block fields
    new_user["is_blocked"] = False
    new_user["blocked_until"] = None
    new_user["blocked_reason"] = None

    result = await db.users.insert_one(new_user)

    return {
        "status": "success",
        "message": "Account created successfully",
        "user_id": str(result.inserted_id),
    }

# ===========================
#            LOGIN
# ===========================
@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, request: Request, db=Depends(get_database)):
    """
    Unified login endpoint for both users and admins.
    - Admin login: Simple auth, no anomaly detection, no login logs
    - User login: Full anomaly detection pipeline with ML
    """
    user = await db.users.find_one({"email": credentials.email})

    # ❌ Invalid email
    if not user:
        await _create_login_log(
            db, credentials.email, None, request,
            getattr(credentials, "device_data", None),
            status="failed",
        )
        raise HTTPException(status_code=400, detail="Invalid email or password")

    # Get user role
    user_role = user.get("role", "user")

    # ========================================
    # ADMIN LOGIN (Simple auth, no anomaly detection)
    # ========================================
    if user_role == "admin":
        # Verify password
        if not verify_password(credentials.password, user["password"]):
            await log_admin_action(
                db, str(user["_id"]), user["email"],
                AuditActions.ADMIN_LOGIN_FAILED,
                details={"reason": "Invalid password"},
                ip_address=admin_get_client_ip(request)
            )
            raise HTTPException(status_code=400, detail="Invalid email or password")

        # Check if blocked
        if user.get("is_blocked", False):
            raise HTTPException(
                status_code=403,
                detail="Admin account is disabled"
            )

        # Create token with role
        token = create_access_token({
            "id": str(user["_id"]),
            "email": user["email"],
            "role": "admin"
        })

        # Update last login and last active
        now = datetime.utcnow()
        update_result = await db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": now, "last_active": now}}
        )
        print(f"[ADMIN LOGIN] Updated last_login and last_active for admin {user['email']} at {now}. Modified: {update_result.modified_count}")

        # Log successful admin login (audit log only, no login_logs)
        await log_admin_action(
            db, str(user["_id"]), user["email"],
            AuditActions.ADMIN_LOGIN,
            ip_address=admin_get_client_ip(request),
            user_agent=get_user_agent(request)
        )

        # Return admin response
        return TokenResponse(
            access_token=token,
            token_type="bearer",
            role="admin",
            requires_2fa=False,
            risk_score=0,
            is_moderate_risk=False,
            is_high_risk=False,
            is_trusted_device=True,
            requires_device_trust=False,
            user={
                "id": str(user["_id"]),
                "email": user["email"],
                "first_name": user.get("first_name", "Admin"),
                "last_name": user.get("last_name", "User"),
                "role": "admin"
            }
        )

    # ========================================
    # USER LOGIN (Full anomaly detection)
    # ========================================
    # ✅ Check if user is already blocked
    if user.get("is_blocked", False):
        blocked_until = user.get("blocked_until")
        blocked_reason = user.get("blocked_reason", "Account suspended")

        # Case 1: Permanent block (no end date)
        if blocked_until is None:
            raise HTTPException(
                status_code=403,
                detail=f"Account suspended. Reason: {blocked_reason}"
            )

        # Case 2: Temporary block - check if still active
        if blocked_until > datetime.utcnow():
            raise HTTPException(
                status_code=403,
                detail=f"Account temporarily blocked until {blocked_until.strftime('%Y-%m-%d %H:%M:%S')}. "
                       f"Reason: {blocked_reason}"
            )

        # Case 3: Block has expired - auto-unblock
        await db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"is_blocked": False, "blocked_until": None, "blocked_reason": None, "status": "active"}}
        )

    # ❌ Wrong password
    if not verify_password(credentials.password, user["password"]):
        login_log_id, context = await _create_login_log(
            db, user["email"], str(user["_id"]), request,
            getattr(credentials, "device_data", None),
            status="failed",
        )

        if context["risk_score"] and context["risk_score"] >= HIGH_RISK_THRESHOLD:
            blocked_until = datetime.utcnow() + timedelta(hours=1)
            await db.users.update_one(
                {"_id": user["_id"]},
                {"$set": {
                    "is_blocked": True,
                    "blocked_until": blocked_until,
                    "blocked_reason": context["anomaly_reason"] or "High risk login detected"
                }}
            )

            subject = "Account temporarily blocked due to suspicious activity"
            body = f"""
Dear {user.get('first_name', 'User')},

Your account has been temporarily blocked for 1 hour due to suspicious login activity.

Reason: {context['anomaly_reason'] or 'Multiple failed login attempts detected'}

You will be able to login again after 1 hour using 2FA verification.

If this wasn't you, please contact support immediately and consider changing your password.

Regards,
Your Security Team
            """
            asyncio.create_task(send_email(user["email"], subject, body))

            # ✅ ADDED: Save blocked login into anomaly logs
            login_log = await db.login_logs.find_one({"_id": ObjectId(login_log_id)})
            login_log["status"] = "blocked"

            # Add push to Redis for blocked login
            try:
                push_recent_login(str(user["_id"]), {**login_log, "_id": login_log_id})
            except Exception:
                pass

            await handle_anomaly(
                {
                    "is_anomaly": True,
                    "event_type": "login",
                    "event_data": login_log,
                },
                db,
            )

            raise HTTPException(
                status_code=403,
                detail=f"Account temporarily blocked until {blocked_until.strftime('%Y-%m-%d %H:%M:%S')}. "
                       f"Reason: {context.get('anomaly_reason', 'High risk activity detected')}"
            )

        raise HTTPException(status_code=400, detail="Invalid email or password")

    # ✅ Password correct
    login_log_id, context = await _create_login_log(
        db=db,
        email=user["email"],
        user_id=str(user["_id"]),
        request=request,
        device_data=getattr(credentials, "device_data", None),
        status="success",
    )

    # 🚨 Block high-risk accounts
    if context["risk_score"] and context["risk_score"] >= HIGH_RISK_THRESHOLD:
        blocked_until = datetime.utcnow() + timedelta(hours=1)
        await db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {
                "is_blocked": True,
                "blocked_until": blocked_until,
                "blocked_reason": context["anomaly_reason"] or "High risk login detected"
            }}
        )
        subject = "Account temporarily blocked due to high-risk login"
        body = f"""
Dear {user.get('first_name', 'User')},

Your account has been temporarily blocked for 1 hour due to a high-risk login attempt.

Reason: {context['anomaly_reason'] or 'High risk login detected'}

You will be able to login again after 1 hour using 2FA verification.

If this wasn't you, please contact support immediately.

Regards,
Your Security Team
        """
        asyncio.create_task(send_email(user["email"], subject, body))

        login_log = await db.login_logs.find_one({"_id": ObjectId(login_log_id)})
        login_log["status"] = "blocked"

        # Add push to Redis for blocked login
        try:
            push_recent_login(str(user["_id"]), {**login_log, "_id": login_log_id})
        except Exception:
            pass

        await handle_anomaly(
            {
                "is_anomaly": True,
                "event_type": "login",
                "event_data": login_log,
            },
            db,
        )

        raise HTTPException(
            status_code=403,
            detail=f"Account temporarily blocked until {blocked_until.strftime('%Y-%m-%d %H:%M:%S')}. "
                   f"Reason: {context.get('anomaly_reason', 'High risk login detected')}"
        )

    # 🔐 Determine OTP and Device Trust
    user_2fa_enabled = user.get("two_factor_enabled", False)
    new_device = not context["is_trusted_device"]
    otp_required = False

    # Debug logging
    print(f"[OTP DECISION] User: {user['email']}")
    print(f"[OTP DECISION] is_trusted_device: {context['is_trusted_device']}")
    print(f"[OTP DECISION] is_moderate: {context['is_moderate']}")
    print(f"[OTP DECISION] risk_score: {context['risk_score']}")
    print(f"[OTP DECISION] 2fa_enabled: {user_2fa_enabled}")

    # ✅ FIXED: Context-aware trust - trusted devices still require OTP for risky contexts
    # Check risk score directly since is_moderate might not be reliable
    if context["is_trusted_device"]:
        # Trusted device - check risk level
        if context["is_moderate"] == 1 or context["risk_score"] >= 45:
            # Moderate/high risk detected - require OTP even on trusted device
            otp_required = True
            print(f"[OTP DECISION] Trusted device but moderate/high risk → OTP REQUIRED")
        else:
            # Trusted device with low risk - no OTP needed
            otp_required = False
            print(f"[OTP DECISION] Trusted device with low risk → NO OTP")
    elif context["is_moderate"] == 1 or context["risk_score"] >= 45:
        # Untrusted device with moderate/high risk - require OTP
        otp_required = True
        print(f"[OTP DECISION] Untrusted device with moderate/high risk → OTP REQUIRED")
    elif context["risk_score"] < 30 and user_2fa_enabled:
        # Low risk but user has 2FA enabled - require OTP
        otp_required = True
        print(f"[OTP DECISION] Low risk but 2FA enabled → OTP REQUIRED")
    else:
        print(f"[OTP DECISION] No OTP required")

    requires_device_trust = new_device and not otp_required

    # 🔐 OTP required → send temp token
    if otp_required:
        print(f"[LOGIN] OTP required for user {user['email']}. is_trusted_device={context['is_trusted_device']}, is_moderate={context['is_moderate']}, risk_score={context['risk_score']}, 2fa_enabled={user.get('two_factor_enabled', False)}")
        await create_or_resend_otp(
            db=db,
            user_id=str(user["_id"]),
            email=user["email"],
            purpose="login_2fa",
        )

        temp_token = create_temp_token({
            "id": str(user["_id"]),
            "email": user["email"],
            "role": user.get("role", "user"),
        })

        return TokenResponse(
            access_token=temp_token,
            token_type="bearer",
            role="user",
            requires_2fa=True,
            requires_device_trust=requires_device_trust,
            risk_score=context["risk_score"],
            is_moderate_risk=context["is_moderate"] == 1,
            is_high_risk=context["is_anomaly"],
            is_trusted_device=context["is_trusted_device"],
            login_log_id=login_log_id,
            anomaly_reason=context["anomaly_reason"],
            user={
                "id": str(user["_id"]),
                "email": user["email"],
                "first_name": user.get("first_name", ""),
                "last_name": user.get("last_name", ""),
                "role": "user"
            }
        )

    # ✅ No OTP → real token
    token = create_access_token({
        "id": str(user["_id"]),
        "email": user["email"],
        "role": user.get("role", "user"),
    })

    # Update last_login and last_active for successful login
    now = datetime.utcnow()
    update_result = await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login": now, "last_active": now}}
    )
    print(f"[LOGIN] Updated last_login and last_active for user {user['email']} at {now}. Modified: {update_result.modified_count}")

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role="user",
        requires_2fa=False,
        requires_device_trust=requires_device_trust,
        risk_score=context["risk_score"],
        is_moderate_risk=context["is_moderate"] == 1,
        is_high_risk=context["is_anomaly"],
        is_trusted_device=context["is_trusted_device"],
        login_log_id=login_log_id,
        anomaly_reason=context["anomaly_reason"],
        user={
            "id": str(user["_id"]),
            "email": user["email"],
            "first_name": user.get("first_name", ""),
            "last_name": user.get("last_name", ""),
            "role": "user"
        }
    )

# ===========================
#  VERIFY LOGIN OTP BODY MODEL
# ===========================
class VerifyOtpRequest(BaseModel):
    otp: str
    purpose: str

# ===========================
#      VERIFY LOGIN OTP
# ===========================
@router.post("/login/verify-otp", response_model=TokenResponse)
async def verify_login_otp(
    request: VerifyOtpRequest,
    db=Depends(get_database),
    current_user=Depends(get_current_temp_user),
):
    try:
        await verify_otp(
            db=db,
            user_id=current_user["id"],
            purpose=request.purpose,
            otp=request.otp,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user_role = current_user.get("role", "user")

    token = create_access_token({
        "id": current_user["id"],
        "email": current_user["email"],
        "role": user_role,
    })

    # ✅ FIXED: Find the most recent login log first, then update it
    # MongoDB update_one doesn't support sort parameter
    most_recent_login = await db.login_logs.find_one(
        {
            "user_id": current_user["id"],
            "status": "success",
        },
        sort=[("login_time", -1)]  # Sort works in find_one
    )
    
    if most_recent_login:
        await db.login_logs.update_one(
            {"_id": most_recent_login["_id"]},
            {"$set": {"otp_verified": True}}
        )
        print(f"[OTP VERIFIED] Marked login {most_recent_login['_id']} as OTP verified for user {current_user['email']}")
    else:
        print(f"[OTP VERIFIED] No recent login log found for user {current_user['email']}")

    # Update last_login and last_active for successful OTP verification
    now = datetime.utcnow()
    update_result = await db.users.update_one(
        {"_id": ObjectId(current_user["id"])},
        {"$set": {"last_login": now, "last_active": now}}
    )
    print(f"[OTP VERIFY] Updated last_login and last_active for user {current_user['email']} at {now}. Modified: {update_result.modified_count}")

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user_role,
        requires_2fa=False,
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
    status: str = "success",
) -> tuple[str, dict]:

    ip_address = get_client_ip(request)
    location = await get_geolocation(ip_address)

    device_info = parse_device_info(device_data or {})
    device_id = device_info["device_id"]
    device_name = device_info.get("device_name", "Unknown Device")

    is_trusted_device = False
    if user_id:
        is_trusted_device = await TrustedDeviceService.is_device_trusted(
            db=db,
            user_id=user_id,
            device_id=device_id,
        )

    previous_login_doc = None
    if user_id:
        previous_login_doc = await db.login_logs.find_one(
            {"user_id": user_id, "status": "success"},
            sort=[("login_time", -1)],
        )

    # ✅ FIXED: Track ALL recent suspicious activity, not just failed attempts
    login_attempts = 1
    recent_failed_count = 0
    last_failed_attempt_time = None
    last_otp_challenge_time = None
    has_unverified_otp = False
    
    if user_id:
        recent_window = datetime.utcnow() - timedelta(minutes=15)
        
        # Count recent failed attempts
        recent_failed_count = await db.login_logs.count_documents({
            "user_id": user_id,
            "status": "failed",
            "login_time": {"$gte": recent_window},
        })
        
        # Get the most recent failed attempt time
        if recent_failed_count > 0:
            last_failed_log = await db.login_logs.find_one(
                {"user_id": user_id, "status": "failed"},
                sort=[("login_time", -1)]
            )
            if last_failed_log:
                last_failed_attempt_time = last_failed_log["login_time"]
        
        # ✅ NEW: Check for recent OTP challenges that weren't verified
        # Look for recent successful logins that triggered OTP (is_moderate=1 or suspicious_pattern=true)
        recent_otp_challenge_window = datetime.utcnow() - timedelta(minutes=5)
        last_otp_challenge = await db.login_logs.find_one(
            {
                "user_id": user_id,
                "status": "success",
                "login_time": {"$gte": recent_otp_challenge_window},
                "$or": [
                    {"is_moderate": 1},
                    {"suspicious_pattern_detected": True},
                    {"risk_score": {"$gte": 45}}
                ]
            },
            sort=[("login_time", -1)]
        )
        
        if last_otp_challenge:
            last_otp_challenge_time = last_otp_challenge["login_time"]
            
            # Check if OTP was actually verified after that challenge
            # Look for a successful login AFTER the challenge but with OTP verification
            # If no such login exists, OTP was never verified
            last_verified_login = await db.login_logs.find_one(
                {
                    "user_id": user_id,
                    "status": "success",
                    "login_time": {"$gt": last_otp_challenge["login_time"]},
                    "otp_verified": True  # We'll need to add this field when OTP is verified
                },
                sort=[("login_time", -1)]
            )
            
            # If there's an OTP challenge but no verified login after it, OTP was not completed
            if not last_verified_login:
                has_unverified_otp = True
                print(f"[SECURITY] User {email} has unverified OTP challenge from {last_otp_challenge_time}")
        
        # For failed attempts: include all previous failures + current
        # For successful attempts: include recent failures (suspicious pattern detection)
        if status == "failed":
            login_attempts = recent_failed_count + 1
        else:
            # Successful login but had recent failures
            login_attempts = recent_failed_count + 1 if recent_failed_count > 0 else 1

    login_log = {
        "user_id": user_id,
        "email": email,
        "device_id": device_id,
        "device_name": device_name,
        "device_info": device_info,
        "ip_address": ip_address,
        "location": location,
        "login_time": datetime.utcnow(),
        "previous_login_time": previous_login_doc["login_time"] if previous_login_doc else None,
        "login_attempts": login_attempts,
        "recent_failed_count": recent_failed_count,
        "last_failed_attempt_time": last_failed_attempt_time,
        "status": status,
        "otp_verified": False,  # ✅ NEW: Track if OTP was verified (will be updated after OTP verification)
    }
    
    # ✅ IMPROVED: Enhanced suspicious pattern detection
    suspicious_pattern = False
    suspicious_reasons = []
    
    if status == "success" and recent_failed_count > 0 and last_failed_attempt_time:
        time_since_last_failure = (datetime.utcnow() - last_failed_attempt_time).total_seconds()
        
        # Pattern 1: Recent failed attempts followed by success
        if time_since_last_failure < 300:  # Extended to 5 minutes
            suspicious_pattern = True
            suspicious_reasons.append(f"{recent_failed_count} failed attempt(s) within last 5 minutes")
            print(f"[SUSPICIOUS PATTERN 1] User {email} had {recent_failed_count} failed attempts, "
                  f"then succeeded {int(time_since_last_failure)}s later")
    
    # ✅ NEW: Pattern 2 - Unverified OTP challenge
    if status == "success" and has_unverified_otp and last_otp_challenge_time:
        time_since_otp_challenge = (datetime.utcnow() - last_otp_challenge_time).total_seconds()
        
        # If there's an unverified OTP challenge within last 10 minutes, still suspicious
        if time_since_otp_challenge < 600:  # 10 minutes
            suspicious_pattern = True
            suspicious_reasons.append(f"Previous OTP challenge not completed ({int(time_since_otp_challenge)}s ago)")
            print(f"[SUSPICIOUS PATTERN 2] User {email} had OTP challenge {int(time_since_otp_challenge)}s ago "
                  f"that was never verified")
    
    # Combine suspicious reasons
    if suspicious_reasons:
        print(f"[SUSPICIOUS PATTERNS DETECTED] {'; '.join(suspicious_reasons)}")

    # ✅ FIXED: Always run risk assessment for all logins (trusted or not)
    try:
        features_df = extract_login_features(
            current_login={
                "login_time": login_log["login_time"],
                "device_id": device_id,
                "device_name": device_name,
                "ip_address": ip_address,
                "location": location,
                "login_attempts": login_attempts,
            },
            previous_login=previous_login_doc,
            login_status=status,
            is_device_trusted=is_trusted_device,  # Pass trust status to feature extractor
        )
        hybrid_result = hybrid_login_decision(features_df)
        
        # Always store the full risk assessment
        login_log.update({
            "rule_flag": hybrid_result.get("rule_flag", 0),
            "rule_score": hybrid_result.get("rule_score", 0.0),
            "ml_score": hybrid_result.get("ml_score", 0.0),
            "hybrid_score": hybrid_result.get("hybrid_score", 0.0),
            "is_moderate": hybrid_result.get("is_moderate", 0),
            "is_anomaly": bool(hybrid_result.get("is_anomaly", 0)),
            "risk_score": int(float(hybrid_result.get("hybrid_score", 0)) * 100),
            "anomaly_reason": hybrid_result.get("anomaly_reason"),
            "is_trusted_device_login": is_trusted_device,
            "suspicious_pattern_detected": suspicious_pattern,  # ✅ NEW: Flag suspicious pattern
        })
        
        # ✅ NEW: Force moderate risk if suspicious pattern detected
        if suspicious_pattern:
            # Override risk to at least moderate
            if login_log["is_moderate"] == 0 and login_log["is_anomaly"] == False:
                login_log["is_moderate"] = 1
                login_log["hybrid_score"] = max(login_log["hybrid_score"], 0.50)
                login_log["risk_score"] = int(float(login_log["hybrid_score"]) * 100)
                
                # Build comprehensive anomaly reason
                if suspicious_reasons:
                    reason_text = "; ".join(suspicious_reasons)
                else:
                    reason_text = "Suspicious login pattern detected"
                
                login_log["anomaly_reason"] = (
                    reason_text
                    if not login_log["anomaly_reason"]
                    else f"{login_log['anomaly_reason']}; {reason_text}"
                )
                print(f"[RISK OVERRIDE] Forcing moderate risk due to suspicious pattern. "
                      f"New risk_score: {login_log['risk_score']}")
        
        # Store suspicious pattern details
        login_log["suspicious_pattern_reasons"] = suspicious_reasons if suspicious_reasons else None
        
        # For trusted devices with successful login and normal context, we can still grant access
        # but we keep the risk score visible for monitoring/analytics
        if is_trusted_device and status == "success":
            location_changed = features_df['location_changed'].iloc[0] if 'location_changed' in features_df.columns else 0
            ip_changed = features_df['ip_changed'].iloc[0] if 'ip_changed' in features_df.columns else 0
            
            if location_changed == 1 or ip_changed == 1 or suspicious_pattern:
                # Context changed or suspicious pattern - mark for step-up auth
                login_log["trust_context_changed"] = True
            else:
                # Normal context - but still show real risk score
                login_log["trust_context_changed"] = False
                
    except Exception as e:
        print(f"[LOGIN LOG ERROR] Risk assessment failed: {e}")
        login_log.update({
            "rule_flag": 0,
            "rule_score": 0.0,
            "ml_score": 0.0,
            "hybrid_score": 0.0,
            "is_moderate": 0,
            "is_anomaly": False,
            "risk_score": 0,
        })

    result = await db.login_logs.insert_one(login_log)

    try:
        push_recent_login(user_id or "unknown", {
            **login_log,
            "_id": str(result.inserted_id),
        })
    except Exception:
        pass

    return str(result.inserted_id), {
        "is_anomaly": login_log["is_anomaly"],
        "is_moderate": login_log["is_moderate"],
        "risk_score": login_log["risk_score"],
        "is_trusted_device": is_trusted_device,
        "anomaly_reason": login_log.get("anomaly_reason"),
    }