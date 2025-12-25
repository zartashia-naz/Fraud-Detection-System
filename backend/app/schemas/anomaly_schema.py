# app/schemas/anomaly_schema.py
from pydantic import BaseModel
from datetime import datetime
from typing import Dict

class AnomalyCreate(BaseModel):
    is_anomaly: bool
    anomaly_type: str  # "login" | "transaction"
    anomaly_score: float
    details: Dict  # raw payload

class AnomalyResponse(BaseModel):
    id: str
    user_id: str
    anomaly_type: str
    anomaly_score: float
    details: Dict
    detected_at: datetime
    is_confirmed: bool