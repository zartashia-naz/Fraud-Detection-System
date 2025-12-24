from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime
from typing import List
from bson import ObjectId

from app.db.mongodb import get_database
from app.core.security import get_current_user
from app.schemas.anomaly_schema import AnomalyCreate
from app.core.dsa.redis_dsa import push_anomaly_score

router = APIRouter(prefix="/anomalies", tags=["Anomalies"])


# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def serialize_mongo(doc: dict) -> dict:
    if "_id" in doc:
        doc["_id"] = str(doc["_id"])
    return doc


# --------------------------------------------------
# INTERNAL HANDLER (USED BY TRANSACTIONS / LOGIN)
# --------------------------------------------------
async def handle_anomaly(event: dict, db):
    """
    Called internally from transaction_route or login_route
    Pushes anomaly to Redis priority queue
    """
    anomaly_id = str(ObjectId())

    payload = {
        "user_id": event.get("event_data", {}).get("user_id"),
        "type": event.get("event_type"),
        "details": event.get("event_data"),
        "created_at": datetime.utcnow().isoformat(),
    }

    score = event.get("event_data", {}).get("risk_score", 50)

    push_anomaly_score(
        anomaly_id=anomaly_id,
        score=float(score),
        payload=payload
    )


# --------------------------------------------------
# CREATE ANOMALY (OPTIONAL MANUAL API)
# --------------------------------------------------
@router.post("")
async def create_anomaly(
    data: AnomalyCreate,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    if not data.is_anomaly:
        raise HTTPException(status_code=400, detail="Not an anomaly")

    anomaly = {
        "user_id": current_user["id"],
        "anomaly_type": data.event_type,
        "details": data.event_data,
        "detected_at": datetime.utcnow(),
        "is_confirmed": False,
    }

    result = await db.anomaly_logs.insert_one(anomaly)
    anomaly["_id"] = result.inserted_id

    return {
        "message": "Anomaly logged successfully",
        "data": serialize_mongo(anomaly),
    }


# --------------------------------------------------
# GET USER ANOMALIES
# --------------------------------------------------
@router.get("")
async def get_my_anomalies(
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    cursor = db.anomaly_logs.find(
        {"user_id": current_user["id"]}
    ).sort("detected_at", -1)

    anomalies = await cursor.to_list(100)
    for a in anomalies:
        serialize_mongo(a)

    return {
        "anomalies": anomalies,
        "count": len(anomalies),
    }


# --------------------------------------------------
# CONFIRM / RESOLVE ANOMALY
# --------------------------------------------------
@router.patch("/{anomaly_id}/confirm")
async def confirm_anomaly(
    anomaly_id: str,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    result = await db.anomaly_logs.update_one(
        {"_id": ObjectId(anomaly_id), "user_id": current_user["id"]},
        {"$set": {"is_confirmed": True}}
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Anomaly not found")

    return {"message": "Anomaly confirmed"}
