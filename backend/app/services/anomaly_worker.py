# app/services/anomaly_worker.py
import asyncio
from datetime import datetime
from app.core.dsa.redis_dsa import pop_top_anomalies

async def persist_anomalies_loop(mongo_db, poll_interval: int = 3):
    """
    Background worker:
    - Pulls top anomalies from Redis (priority queue)
    - Persists them into MongoDB (anomaly_logs collection)
    """

    # 🛡️ Safety guard
    if not isinstance(poll_interval, (int, float)) or poll_interval <= 0:
        poll_interval = 3

    while True:
        try:
            items = pop_top_anomalies(10)

            if items:
                docs = []
                for anomaly_id, score, payload in items:
                    if not payload:
                        continue

                    docs.append({
                        "anomaly_id": anomaly_id,
                        "user_id": payload.get("user_id"),
                        "anomaly_type": payload.get("type"),
                        "anomaly_score": score,
                        "details": payload.get("details"),
                        "detected_at": datetime.utcnow(),
                        "raw_payload": payload,
                    })

                if docs:
                    await mongo_db.anomaly_logs.insert_many(docs)
                    print(f"✅ Persisted {len(docs)} anomalies to MongoDB")

        except Exception as e:
            print("❌ Error in persist_anomalies_loop:", e)

        await asyncio.sleep(poll_interval)
