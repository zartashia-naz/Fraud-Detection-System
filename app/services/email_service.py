import resend
from app.core.config import settings

# Initialize Resend once
resend.api_key = settings.RESEND_API_KEY


async def send_email(to_email: str, subject: str, body: str):
    """
    Sends email using Resend (HTTP-based).
    Function signature unchanged to avoid breaking imports.
    """

    try:
        resend.Emails.send({
            "from": settings.EMAIL_FROM,   # SYSTEM EMAIL
            "to": to_email,                # USER EMAIL
            "subject": subject,
            "text": body,                  # plain text (perfect for OTP)
        })

    except Exception as e:
        # Important: log but don't crash the whole API
        print(f"❌ Email sending failed: {e}")
        raise
