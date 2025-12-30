# app/api/v1/routes/dsa_test_routes.py
from fastapi import APIRouter, Depends
from app.schemas.transaction_schema import TransactionCreate
from app.schemas.login_log_schema import LoginLogCreate
from app.schemas.anomaly_schema import AnomalyCreate
from app.db.mongodb import get_database
from app.core.dsa.redis_dsa import (
    push_recent_txn, get_recent_txns,
    push_recent_login, get_recent_logins,
    record_login_attempt, count_login_attempts,
    push_anomaly_score, peek_top_anomalies, pop_top_anomalies,
    set_last_device, set_last_ip
)
from app.core.dsa.mongo_dsa import MongoDSA
from datetime import datetime
import uuid

router = APIRouter(prefix="/dsa", tags=["DSA Test"])

@router.post("/transactions/insert")
async def insert_transaction(txn: TransactionCreate, db=Depends(get_database)):
    t = txn.dict()
    t["transaction_date"] = t.get("transaction_date") or datetime.utcnow()
    t["anomaly_score"] = t.get("anomaly_score", 0.0)
    res = await db.transactions.insert_one(t)
    push_recent_txn(txn.user_id, t)
    return {"inserted_id": str(res.inserted_id)}

@router.get("/transactions/recent/{user_id}")
async def recent_transactions(user_id: str):
    return get_recent_txns(user_id)

@router.get("/transactions/query")
async def transactions_query(user_id: str | None = None, from_ts: str | None = None, to_ts: str | None = None, sort_by: str = "anomaly_score", limit: int = 100, db=Depends(get_database)):
    from_dt = datetime.fromisoformat(from_ts) if from_ts else None
    to_dt = datetime.fromisoformat(to_ts) if to_ts else None
    m = MongoDSA(db)
    return await m.get_transactions_by_date_range(user_id=user_id, from_dt=from_dt, to_dt=to_dt, sort_by=sort_by, limit=limit)

@router.post("/logins/insert")
async def insert_login(log: LoginLogCreate, db=Depends(get_database)):
    d = log.dict()
    d["login_time"] = d.get("login_time") or datetime.utcnow()
    res = await db.login_logs.insert_one(d)
    push_recent_login(log.user_id, d)
    count = record_login_attempt(log.user_id)
    if log.device_id:
        set_last_device(log.user_id, log.device_id)
    if log.ip_address:
        set_last_ip(log.user_id, log.ip_address)
    return {"inserted_id": str(res.inserted_id), "attempts_window": count}

@router.get("/logins/recent/{user_id}")
async def recent_logins(user_id: str):
    return get_recent_logins(user_id)

@router.get("/logins/attempts/{user_id}")
async def attempts_count(user_id: str):
    return {"count": count_login_attempts(user_id)}

@router.post("/anomalies/push")
async def push_anomaly(a: AnomalyCreate):
    aid = f"{a.user_id}:{uuid.uuid4().hex[:8]}"
    payload = {"user_id": a.user_id, "type": a.anomaly_type, "score": a.anomaly_score, "details": a.details}
    push_anomaly_score(aid, float(a.anomaly_score), payload)
    return {"anomaly_id": aid, "pushed": True}

@router.get("/anomalies/peek")
async def peek():
    return peek_top_anomalies(10)

@router.post("/anomalies/pop")
async def pop_top(limit: int = 5):
    return pop_top_anomalies(limit)
