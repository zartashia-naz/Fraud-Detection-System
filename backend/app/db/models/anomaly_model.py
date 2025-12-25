from pydantic import BaseModel, Field
from datetime import datetime
from typing import Dict

class AnomalyModel(BaseModel):
    user_id: str
    anomaly_type: str            # "login" | "transaction"
    anomaly_score: float
    details: Dict
    raw_payload: Dict
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    is_confirmed: bool = False


    class Config:
        arbitrary_types_allowed = True
