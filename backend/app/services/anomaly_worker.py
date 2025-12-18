# app/services/anomaly_worker.py
import asyncio
from app.core.dsa.redis_dsa import pop_top_anomalies
from app.db.mongodb import get_client
from datetime import datetime

async def persist_anomalies_loop(mongo_db, poll_interval=3):
    """
    Run in background: pop top anomalies and persist to Mongo's anomaly_logs.
    Call this as an asyncio task in FastAPI startup if you want.
    """
    while True:
        items = pop_top_anomalies(10)
        if items:
            docs = []
            for aid, score, payload in items:
                doc = {
                    "anomaly_id": aid,
                    "user_id": payload.get("user_id"),
                    "anomaly_type": payload.get("type"),
                    "anomaly_score": score,
                    "details": payload.get("details"),
                    "detected_at": datetime.utcnow(),
                    "raw_payload": payload
                }
                docs.append(doc)
            if docs:
                await mongo_db.anomaly_logs.insert_many(docs)
        await asyncio.sleep(poll_interval)
