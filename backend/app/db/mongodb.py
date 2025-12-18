from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument
from fastapi import Depends
from app.core.config import settings

class MongoDB:
    client: AsyncIOMotorClient = None

mongodb = MongoDB()


# 🔹 Return database object
async def get_database():
    return mongodb.client[settings.MONGO_DB_NAME]


# 🔹 Connect MongoDB (called on startup)
async def connect_to_mongo():
    mongodb.client = AsyncIOMotorClient(settings.MONGO_URI)
    print("📌 Connected to MongoDB")


# 🔹 Close connection (shutdown)
async def close_mongo_connection():
    mongodb.client.close()
    print("❌ MongoDB Connection Closed")


# ✅ ADD THIS FUNCTION
def get_client():
    """Return raw MongoDB client"""
    return mongodb.client
