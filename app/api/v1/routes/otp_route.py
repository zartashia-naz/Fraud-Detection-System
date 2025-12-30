from fastapi import APIRouter, Depends, HTTPException
from app.db.mongodb import get_database
from app.core.security import (get_current_user,get_current_temp_user)   # 🔥 ADDITION

from app.services.otp_service import create_or_resend_otp
from app.services.otp_verify_service import verify_otp

router = APIRouter(prefix="/otp", tags=["OTP"])

@router.post("/send")
async def send_otp(
    purpose: str,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    try:
        return await create_or_resend_otp(
            db=db,
            user_id=current_user["id"],
            email=current_user["email"],
            purpose=purpose,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/verify")
async def verify_otp_api(
    purpose: str,
    otp: str,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    try:
        await verify_otp(
            db=db,
            user_id=current_user["id"],
            purpose=purpose,
            otp=otp,
        )
        return {"message": "OTP verified successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))




# =====================================================
# 🔐 ADDITION: LOGIN 2FA OTP ROUTES (TEMP TOKEN)
# =====================================================

@router.post("/login/send")
async def send_login_otp(
    db=Depends(get_database),
    current_user=Depends(get_current_temp_user),
):
    """
    Used ONLY after login when requires_2fa = true
    """
    try:
        return await create_or_resend_otp(
            db=db,
            user_id=current_user["id"],
            email=current_user["email"],
            purpose="login",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login/verify")
async def verify_login_otp(
    otp: str,
    db=Depends(get_database),
    current_user=Depends(get_current_temp_user),
):
    """
    Verifies login OTP.
    After success, frontend should call login-complete
    endpoint to get final access token.
    """
    try:
        await verify_otp(
            db=db,
            user_id=current_user["id"],
            purpose="login",
            otp=otp,
        )
        return {"message": "Login OTP verified successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))