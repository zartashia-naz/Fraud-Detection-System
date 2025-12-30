import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.core.config import settings

async def send_email(to_email: str, subject: str, body: str):
    msg = MIMEMultipart()
    msg["From"] = settings.SMTP_USER          # SYSTEM EMAIL
    msg["To"] = to_email                      # USER EMAIL
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
    server.starttls()

    # 🔐 Login with SYSTEM email only
    server.login(settings.SMTP_USER, settings.SMTP_PASS)

    server.sendmail(
        settings.SMTP_USER,
        to_email,
        msg.as_string()
    )

    server.quit()
