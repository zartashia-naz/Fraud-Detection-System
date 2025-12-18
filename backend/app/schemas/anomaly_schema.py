from pydantic import BaseModel
from datetime import datetime
from typing import Dict, Optional

class AnomalyCreate(BaseModel):
    is_anomaly: bool
    event_type: str         # "transaction" or "login"
    event_data: Dict        # raw payload sent from login/transaction

class AnomalyResponse(BaseModel):
    id: str
    user_id: str
    anomaly_type: str
    details: Dict
    detected_at: datetime
    is_confirmed: bool
