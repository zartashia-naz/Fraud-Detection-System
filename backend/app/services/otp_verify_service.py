# from datetime import datetime

# async def verify_otp(
#     db,
#     user_id: str,
#     purpose: str,
#     otp: str,
# ):
#     record = await db.otps.find_one({
#         "user_id": user_id,
#         "purpose": purpose,
#         "otp": otp,
#         "is_used": False,
#     })

#     if not record:
#         raise ValueError("Invalid OTP")

#     if record["expires_at"] < datetime.utcnow():
#         raise ValueError("OTP expired")

#     await db.otps.update_one(
#         {"_id": record["_id"]},
#         {"$set": {"is_used": True, "verified_at": datetime.utcnow()}}
#     )

#     return True


from datetime import datetime
async def verify_otp(
    db,
    user_id: str,
    purpose: str,
    otp: str,
    metadata: dict | None = None,
):

    now = datetime.utcnow()

    query = {
        "user_id": user_id,
        "purpose": purpose,
        "otp": otp,
        "is_used": False,
        "expires_at": {"$gt": now}
    }

    if metadata is not None:
        query["metadata"] = metadata
    else:
        query["metadata"] = None

    record = await db.otps.find_one(query)

    if not record:
        raise ValueError("Invalid OTP")

    if record["expires_at"] < now:
        raise ValueError("OTP expired")

    await db.otps.update_one(
        {"_id": record["_id"]},
        {"$set": {"is_used": True, "verified_at": datetime.utcnow()}}
    )

    return True                                                                                                                                                                                          