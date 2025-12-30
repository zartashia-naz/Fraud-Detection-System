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
from app.api.v1.routes.user_route import router as user_router
from app.api.v1.routes.anomaly_route import router as anomaly_router

from app.api.v1.routes.trusted_device_route import router as trusted_device_router
from app.api.v1.routes.otp_route import router as otp_router
from app.api.v1.routes.admin_routes import router as admin_router

# DSA (Mongo) + anomaly worker
from app.core.dsa.mongo_dsa import MongoDSA
from app.services.anomaly_worker import persist_anomalies_loop
from app.core.admin_security import hash_password
from datetime import datetime


# -----------------------------
# FASTAPI APP
# -----------------------------
app = FastAPI(
    title="Fraud Detection System",
    version="1.0.0",
    description="Backend API for transaction & login anomaly detection"
)
app.include_router(user_router, prefix="/api/v1")

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
         "http://127.0.0.1:8081",
         "http://localhost:8081",
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
app.include_router(anomaly_router, prefix="/api/v1")
app.include_router(admin_router, prefix="/api/v1/admin", tags=["Admin"])
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

    # Create admin-specific indexes
    await db.audit_logs.create_index([("admin_id", 1), ("created_at", -1)])
    await db.audit_logs.create_index([("action", 1), ("created_at", -1)])
    await db.fraud_alerts.create_index([("status", 1), ("severity", -1)])
    await db.fraud_alerts.create_index([("created_at", -1)])
    await db.detection_rules.create_index("name", unique=True)
    await db.users.create_index([("status", 1), ("created_at", -1)])
    await db.users.create_index([("is_blocked", 1)])
    await db.users.create_index([("role", 1)])  # Index for role-based queries
    await db.transactions.create_index([("status", 1), ("created_at", -1)])
    print("🔧 Admin indexes created")

    # Create default admin account in 'users' collection if not exists
    existing_admin = await db.users.find_one({
        "email": "admin@linklock.com",
        "role": "admin"
    })
    if not existing_admin:
        default_admin = {
            "email": "admin@linklock.com",
            "password": hash_password("Admin@123"),  # Uses 'password' field like regular users
            "first_name": "Admin",
            "last_name": "User",
            "phone": "",
            "cnic": "",
            "role": "admin",  # Role-based access control
            "status": "active",
            "two_factor_enabled": False,
            "is_blocked": False,
            "blocked_until": None,
            "blocked_reason": None,
            "created_at": datetime.utcnow()
        }
        await db.users.insert_one(default_admin)
        print("👤 Default admin account created (admin@linklock.com / Admin@123)")
    else:
        print("👤 Admin account already exists")

    # Initialize system settings if not exists
    existing_settings = await db.system_settings.find_one({})
    if not existing_settings:
        default_settings = {
            "security": {
                "auto_block_enabled": True,
                "auto_block_threshold": 85,
                "max_login_attempts": 5,
                "session_timeout_minutes": 30,
                "require_2fa_for_high_risk": True,
                "lockout_duration_minutes": 30
            },
            "detection": {
                "risk_threshold_flag": 50,
                "risk_threshold_block": 85,
                "ml_model_version": "v2.3.1",
                "real_time_monitoring": True,
                "rule_weight": 0.4,
                "ml_weight": 0.6
            },
            "notifications": {
                "email_alerts_enabled": True,
                "sms_alerts_enabled": False,
                "alert_email_recipients": [],
                "alert_cooldown_minutes": 5
            },
            "updated_at": datetime.utcnow()
        }
        await db.system_settings.insert_one(default_settings)
        print("⚙️ Default system settings initialized")

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
