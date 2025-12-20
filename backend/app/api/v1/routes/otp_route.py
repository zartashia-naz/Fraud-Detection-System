from fastapi import APIRouter, Depends, HTTPException
from app.db.mongodb import get_database
from app.core.security import get_current_user
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
