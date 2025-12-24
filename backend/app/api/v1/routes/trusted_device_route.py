# ============================================================================  
# FILE: backend/app/api/v1/routes/trusted_device_route.py  
# ============================================================================  

from fastapi import APIRouter, HTTPException, Depends, status
from app.db.mongodb import get_database
from app.core.security import get_current_user
from app.schemas.trusted_device_schema import (
    TrustDeviceRequest,
    TrustedDeviceResponse,
    TrustedDevicesListResponse,
    RevokeDeviceRequest
)
from app.services.trusted_device_service import TrustedDeviceService
from bson import ObjectId
from bson.errors import InvalidId

router = APIRouter(prefix="/trusted-devices", tags=["Trusted Devices"])


@router.post("/trust", status_code=status.HTTP_201_CREATED)
async def trust_device(
    request: TrustDeviceRequest,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Trust a device from a login log entry.
    The frontend must send `login_log_id` returned from login logs insertion.
    """
    user_id = str(current_user["id"])

    # Convert login_log_id safely to ObjectId
    try:
        login_log_obj_id = ObjectId(request.login_log_id)
    except InvalidId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid login log ID"
        )

    # Find the login log entry
    login_log = await db.login_logs.find_one({"_id": login_log_obj_id})
    if not login_log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Login log not found"
        )

    # Verify login log belongs to current user
    if str(login_log.get("user_id")) != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This login does not belong to you"
        )

    # Check if device is already trusted
    is_trusted = await TrustedDeviceService.is_device_trusted(
        db=db,
        user_id=user_id,
        device_id=login_log["device_id"]
    )

    if is_trusted:
        return {
            "status": "success",
            "message": "Device is already trusted",
            "already_trusted": True
        }

    # Trust the device
    trusted_device_id = await TrustedDeviceService.trust_device(
        db=db,
        user_id=user_id,
        device_id=login_log["device_id"],
        device_name=login_log.get("device_name", "Unknown Device"),
        device_info=login_log.get("device_info", {}),
        ip_address=login_log["ip_address"],
        location=login_log.get("location", {})
    )

    return {
        "status": "success",
        "message": "Device trusted successfully",
        "trusted_device_id": trusted_device_id,
        "already_trusted": False
    }


@router.get("", response_model=TrustedDevicesListResponse)
async def get_trusted_devices(
    current_user: dict = Depends(get_current_user),
    db = Depends(get_database)
):
    user_id = str(current_user["id"])

    devices = await TrustedDeviceService.get_trusted_devices(
        db=db,
        user_id=user_id,
        active_only=True
    )

    cleaned_devices = []

    for device in devices:
        device["id"] = str(device["_id"])
        device.pop("_id")  # 🔥 CRITICAL FIX
        cleaned_devices.append(device)

    return {
        "devices": cleaned_devices,
        "total": len(cleaned_devices)
    }


@router.post("/revoke", status_code=status.HTTP_200_OK)  # ✅ Changed DELETE to POST
async def revoke_device(
    request: RevokeDeviceRequest,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Revoke a trusted device.
    
    After revoking, the device will be treated as untrusted
    and will trigger anomaly detection again.
    """
    user_id = str(current_user["id"])  
    
    success = await TrustedDeviceService.revoke_device(
        db=db,
        user_id=user_id,
        device_id=request.device_id
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Trusted device not found"
        )
    
    return {
        "status": "success",
        "message": "Device revoked successfully"
    }