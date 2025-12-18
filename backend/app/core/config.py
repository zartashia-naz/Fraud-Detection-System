import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "Fraud Detection System"
    
    # MongoDB Config
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "fraud_detection"

    class Config:
        env_file = ".env"

settings = Settings()
