# app/core/dsa/mongo_dsa.py
from datetime import datetime, timedelta
from pymongo import DESCENDING

class MongoDSA:
    def __init__(self, db):
        """
        db is Motor database object (async)
        e.g. db = await get_database()
        """
        self.db = db

    # generic date-range transaction query, sorted by field (anomaly_score, amount, timestamp)
    async def get_transactions_by_date_range(
        self, user_id: str | None = None,
        from_dt: datetime | None = None, to_dt: datetime | None = None,
        sort_by: str = "anomaly_score", desc: bool = True,
        limit: int = 100, skip: int = 0
    ):
        q = {}
        if user_id:
            q["user_id"] = user_id
        if from_dt or to_dt:
            q["transaction_date"] = {}
            if from_dt:
                q["transaction_date"]["$gte"] = from_dt
            if to_dt:
                q["transaction_date"]["$lte"] = to_dt

        sort_dir = DESCENDING if desc else 1
        cursor = self.db.transactions.find(q).sort(sort_by, sort_dir).skip(skip).limit(limit)
        return await cursor.to_list(length=limit)

    # anomalies: get anomalies in a date range sorted by anomaly_score desc
    async def get_anomalies_by_date_range(self, from_dt: datetime | None = None, to_dt: datetime | None = None, limit: int = 100):
        q = {}
        if from_dt or to_dt:
            q["detected_at"] = {}
            if from_dt:
                q["detected_at"]["$gte"] = from_dt
            if to_dt:
                q["detected_at"]["$lte"] = to_dt

        cursor = self.db.anomaly_logs.find(q).sort("anomaly_score", DESCENDING).limit(limit)
        return await cursor.to_list(length=limit)

    # create helpful indexes (run at startup)
    async def ensure_indexes(self):
        await self.db.transactions.create_index([("user_id", 1), ("transaction_date", -1)])
        await self.db.transactions.create_index([("anomaly_score", -1)])
        await self.db.login_logs.create_index([("user_id", 1), ("login_time", -1)])
        await self.db.anomaly_logs.create_index([("user_id", 1), ("detected_at", -1)])
        await self.db.anomaly_logs.create_index([("anomaly_score", -1)])
