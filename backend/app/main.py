# main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import logging

from app.core.config import settings
from app.db.mongodb import connect_to_mongo, close_mongo_connection, get_client

# Your real routers
from app.api.v1.routes.auth_route import router as auth_router
from app.api.v1.routes.transaction_route import router as transaction_router
from app.api.v1.routes.login_log_route import router as login_log_router
from app.api.v1.routes.test_dsa_routes import router as dsa_test_router
from app.api.v1.routes.test_db_route import router as test_db_router
from app.api.v1.routes.trusted_device_route import router as trusted_device_router
from app.api.v1.routes.otp_route import router as otp_router

# DSA (Mongo) + anomaly worker
from app.core.dsa.mongo_dsa import MongoDSA
from app.services.anomaly_worker import persist_anomalies_loop


# -----------------------------
# FASTAPI APP
# -----------------------------
app = FastAPI(
    title="Fraud Detection System",
    version="1.0.0",
    description="Backend API for transaction & login anomaly detection"
)


# -----------------------------
# CORS MIDDLEWARE
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# ROUTERS
# -----------------------------
app.include_router(auth_router, prefix="/api/v1/auth")
app.include_router(transaction_router, prefix="/api/v1")
app.include_router(login_log_router, prefix="/api/v1")
app.include_router(dsa_test_router, prefix="/api/v1")
app.include_router(test_db_router)
app.include_router(trusted_device_router, prefix="/api/v1")
app.include_router(otp_router, prefix="/api/v1")

# -----------------------------
# STARTUP EVENT
# -----------------------------
@app.on_event("startup")
async def startup_event():
    print("🚀 Starting Fraud Detection API...")
    await connect_to_mongo()
    print("✅ MongoDB connected")

    # Create indexes
    client = get_client()
    db = client[settings.MONGO_DB_NAME]

    mongo_dsa = MongoDSA(db)
    await mongo_dsa.ensure_indexes()
    print("🔧 Indexes created")

    # Start anomaly worker in background
    loop = asyncio.get_event_loop()
    loop.create_task(persist_anomalies_loop(db))


# -----------------------------
# SHUTDOWN EVENT
# -----------------------------
@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 Shutting down API...")
    await close_mongo_connection()
    print("❌ MongoDB connection closed")


# -----------------------------
# ROOT ENDPOINT
# -----------------------------
@app.get("/", tags=["Health"])
def root():
    return {
        "message": "Fraud Detection Backend Running",
        "version": "1.0.0",
        "docs": "/docs"
    }
