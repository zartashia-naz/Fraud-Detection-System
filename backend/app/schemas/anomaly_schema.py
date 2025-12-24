from pydantic import BaseModel
from datetime import datetime
from typing import Dict

class AnomalyCreate(BaseModel):
    is_anomaly: bool
    event_type: str              # "transaction" | "login"
    anomaly_score: float
    event_data: Dict             # raw event payload

class AnomalyResponse(BaseModel):
    id: str
    user_id: str
    anomaly_type: str
    anomaly_score: float
    details: Dict
    detected_at: datetime
    is_confirmed: bool
