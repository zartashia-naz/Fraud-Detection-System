import os
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    PROJECT_NAME: str = "Fraud Detection System"
    
    # MongoDB Config
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "fraud_detection"

    # 📧 SMTP (ADD THESE)
    # SMTP_HOST: str = Field(..., env="SMTP_HOST")
    # SMTP_PORT: int = Field(..., env="SMTP_PORT")
    # SMTP_USER: str = Field(..., env="SMTP_USER")
    # SMTP_PASS: str = Field(..., env="SMTP_PASS")


    RESEND_API_KEY: str
    EMAIL_FROM: str

    class Config:
        env_file = ".env"

settings = Settings()
