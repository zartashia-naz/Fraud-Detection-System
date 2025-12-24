# app/api/v1/routes/user_route.py

from fastapi import APIRouter, Depends, HTTPException, status
from bson import ObjectId
from app.db.mongodb import get_database
from app.schemas.user_schema import UserResponse
from app.core.security import get_current_user  # Reuse the existing get_current_user (returns payload)

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)

# New dependency: gets the full user document from DB using the validated payload
async def get_current_user_db(
    payload: dict = Depends(get_current_user),
    db = Depends(get_database)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    user_id: str = payload.get("id")
    if user_id is None:
        raise credentials_exception

    try:
        user = await db["users"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        raise credentials_exception

    if user is None:
        raise credentials_exception

    return user


@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: dict = Depends(get_current_user_db)):
    return {
        "id": str(current_user["_id"]),
        "first_name": current_user["first_name"],
        "last_name": current_user["last_name"],
        "email": current_user["email"],
        "phone": current_user["phone"],
        "cnic": current_user["cnic"],
    }

# ... existing imports ...

@router.patch("/me", response_model=UserResponse)
async def update_users_me(
    update_data: dict,  # Or create a Pydantic model for validation
    current_user: dict = Depends(get_current_user_db),
    db = Depends(get_database)
):
    allowed_fields = {"first_name", "last_name", "phone", "cnic"}  # Email not editable
    filtered_update = {k: v for k, v in update_data.items() if k in allowed_fields and v != ""}

    if not filtered_update:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    try:
        result = await db["users"].update_one(
            {"_id": current_user["_id"]},
            {"$set": filtered_update}
        )

        if result.modified_count == 0:
            raise HTTPException(status_code=400, detail="No changes made")

        # Fetch updated user
        updated_user = await db["users"].find_one({"_id": current_user["_id"]})
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to update profile")

    return {
        "id": str(updated_user["_id"]),
        "first_name": updated_user["first_name"],
        "last_name": updated_user["last_name"],
        "email": updated_user["email"],
        "phone": updated_user["phone"],
        "cnic": updated_user["cnic"],
    }