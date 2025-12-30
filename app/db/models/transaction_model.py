from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class TransactionModel(BaseModel):
    """
    Core transaction record stored in MongoDB.

    Enriched with the full output of `hybrid_transaction_decision` from
    hybrid_transaction.py (rule-based + Isolation Forest + Autoencoder).
    All hybrid detection fields are optional so the model can be used
    both before and after anomaly detection.
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

    # Hybrid detection outputs (directly aligned with hybrid_transaction_decision return dict)
    rule_flag: Optional[int] = None                 # 0/1 from rule-based decision
    rule_score: Optional[float] = None              # 0.0–1.0 normalized rule score
    rule_details: Optional[Dict[str, Any]] = None   # per-rule breakdown with scores/messages
    ml_iso_score: Optional[float] = None            # Isolation Forest anomaly score (0.0–1.0)
    ml_ae_score: Optional[float] = None             # Autoencoder anomaly score (0.0–1.0)
    ml_score: Optional[float] = None                # combined ML score (0.0–1.0)
    hybrid_score: Optional[float] = None            # final fused score (0.0–1.0)
    is_moderate: Optional[int] = None               # 1 if moderate risk, 0 otherwise
    is_anomaly: Optional[int] = None                # 1 if high-risk anomaly, 0 otherwise

    # Additional derived / UI-friendly fields (recommended additions)
    severity: Optional[str] = None                  # "high", "moderate", or "normal" (derived from thresholds)
    reasons: Optional[List[Dict[str, Any]]] = None
             # list of human-readable reasons (from rules + ML contributions)
    reason_summary: Optional[str] = None            # joined string of reasons for quick display
    risk_score: Optional[int] = None                # optional 0–100 risk scale for UI (e.g., int(hybrid_score * 100))

    class Config:
        from_attributes = True
        # Allow population from dicts with extra fields (e.g., "event_type" from hybrid output)
        extra = "allow"