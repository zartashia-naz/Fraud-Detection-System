from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class TransactionModel(BaseModel):
    """
    Core transaction record stored in MongoDB.

    Now also enriched with hybrid anomaly detection results produced by
    `hybrid_transaction_decision` (rule-based + Isolation Forest + Autoencoder).
    """

    # Identity / core fields
    user_id: str
    amount: float
    category: str
    ip: str
    device_id: str

    # Auto-fetched context fields
    transaction_date: datetime = Field(default_factory=datetime.utcnow)
    location: Optional[Dict[str, Any]] = None
    merchant_id: Optional[str] = None
    transaction_duration: Optional[float] = None
    previous_transaction_date: Optional[datetime] = None
    description: Optional[str] = None

    # Hybrid detection outputs
    rule_flag: Optional[int] = None                 # 0/1 rule decision
    rule_score: Optional[float] = None              # 0.0–1.0 normalized rule score
    rule_details: Optional[Dict[str, Any]] = None   # detailed per-rule breakdown
    ml_iso_score: Optional[float] = None            # Isolation Forest score (0.0–1.0)
    ml_ae_score: Optional[float] = None             # Autoencoder reconstruction score (0.0–1.0)
    ml_score: Optional[float] = None                # combined ML score (0.0–1.0)
    hybrid_score: Optional[float] = None            # final fused score (0.0–1.0)
    is_moderate: Optional[int] = None               # 0/1 moderate suspicion
    is_anomaly: Optional[bool] = False              # final anomaly decision
    risk_score: Optional[int] = None                # optional 0–100 risk scale for UI

    class Config:
        from_attributes = True