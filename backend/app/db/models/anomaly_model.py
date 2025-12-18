from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Dict

class AnomalyModel(BaseModel):
    user_id: str
    anomaly_type: str      # "login" or "transaction"
    details: Dict          # entire event stored here
    detected_at: datetime = datetime.utcnow()
    is_confirmed: bool = False  # In case admins review anomalies
