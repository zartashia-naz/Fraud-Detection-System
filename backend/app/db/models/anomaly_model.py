from pydantic import BaseModel, Field
from datetime import datetime
from typing import Dict, Optional

class AnomalyModel(BaseModel):
    user_id: str
    anomaly_type: str            # "transaction" | "login"
    anomaly_score: float
    details: Dict                # processed anomaly details
    raw_payload: Dict            # original event payload
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    is_confirmed: bool = False   # admin/user confirmation later

    class Config:
        arbitrary_types_allowed = True
