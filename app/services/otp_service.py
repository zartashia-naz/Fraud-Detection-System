import random
from datetime import datetime, timedelta
from app.services.email_service import send_email

OTP_EXPIRY_MINUTES = 5
OTP_RESEND_COOLDOWN_SECONDS = 60

async def create_or_resend_otp(
    db,
    user_id: str,
    email: str,
    purpose: str,
    metadata: dict | None = None,
):

    now = datetime.utcnow()

    query = {
        "user_id": user_id,
        "purpose": purpose,
        "is_used": False,
        "expires_at": {"$gt": now},
    }

    if metadata is not None:
        query["metadata"] = metadata
    else:
        query["metadata"] = None

    existing = await db.otps.find_one(query)

    if existing:
        last_sent = existing.get("last_sent_at")
        if last_sent and (now - last_sent).total_seconds() < OTP_RESEND_COOLDOWN_SECONDS:
            return {
                "status": "cooldown",
                "message": "OTP already sent. Please wait before resending.",
            }

        await db.otps.update_one(
            {"_id": existing["_id"]},
            {"$set": {"last_sent_at": now}},
        )
        otp_code = existing["otp"]

    else:
        otp_code = str(random.randint(100000, 999999))

        await db.otps.insert_one({
            "user_id": user_id,
            "email": email,
            "otp": otp_code,
            "purpose": purpose,
            "metadata": metadata,
            "is_used": False,
            "created_at": now,
            "last_sent_at": now,
            "expires_at": now + timedelta(minutes=OTP_EXPIRY_MINUTES),
        })


    # 📧 Send email (wrapped safely)
    try:
        await send_email(
            to_email=email,
            subject="Your OTP Code",
            body=(
                f"Your OTP for {purpose.replace('_', ' ')} is: {otp_code}\n\n"
                f"This OTP will expire in {OTP_EXPIRY_MINUTES} minutes."
            )
        )

    except Exception as e:
        # Optional: log error for debugging
        print(f"❌ OTP email failed for {email}: {e}")

        return {
            "status": "failed",
            "message": "Unable to send OTP. Please try again later.",
        }

    return {
        "status": "sent",
        "message": "OTP sent successfully",
    }
