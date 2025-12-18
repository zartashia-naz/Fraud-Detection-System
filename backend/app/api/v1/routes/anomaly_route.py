from fastapi import APIRouter
from app.db.models.anomaly_model import AnomalyModel

router = APIRouter(prefix="/anomalies", tags=["Anomalies"])

async def handle_anomaly(data: dict, db):
    """
    data format:
    {
        "is_anomaly": bool,
        "event_type": "transaction" | "login",
        "event_data": {...}
    }
    """

    is_anomaly = data["is_anomaly"]
    event_type = data["event_type"]
    event_data = data["event_data"]

    if is_anomaly:
        # Save anomaly event
        anomaly_doc = AnomalyModel(
            user_id=event_data.get("user_id"),
            anomaly_type=event_type,
            details=event_data
        )

        await db.anomaly_logs.insert_one(anomaly_doc.dict())

        return {
            "status": "anomaly_detected",
            "message": f"{event_type} anomaly saved."
        }

    # ---------- NORMAL BEHAVIOUR ----------


    return {
            "status": "normal",
            "message": f"Normal {event_type} saved successfully."
        }
