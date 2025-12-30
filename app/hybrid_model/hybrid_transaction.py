"""
Hybrid Transaction Anomaly Detection
----------------------------------
Combines:
1. Rule-based transaction detection (DSA rules)
2. ML-based detection using Isolation Forest + Autoencoder

Location:
backend/app/hybrid_model/hybrid_transaction.py
"""

import os
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional

from app.core.transaction_rule_based import compute_rule_based_score
from tensorflow.keras.models import load_model

# --------------------------------------------------
# PATH / ARTIFACT CONFIG
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

ISO_MODEL_PATH = os.path.join(
    BASE_DIR, "ml", "Transaction_pipeline", "transaction_isolation_forest_model.pkl"
)
ISO_SCALER_PATH = os.path.join(
    BASE_DIR, "ml", "Transaction_pipeline", "transaction_scaler.pkl"
)
AE_MODEL_PATH = os.path.join(
    BASE_DIR, "ml", "Transaction_pipeline", "transaction_autoencoder_model.h5"
)
AE_SCALER_PATH = os.path.join(
    BASE_DIR, "ml", "Transaction_pipeline", "transaction_autoencoder_scaler.pkl"
)

# --------------------------------------------------
# LOAD MODELS / SCALERS
# --------------------------------------------------
try:
    isolation_forest = joblib.load(ISO_MODEL_PATH)
except Exception as e:
    raise RuntimeError(f"Failed to load Isolation Forest model: {e}")

try:
    iso_scaler = joblib.load(ISO_SCALER_PATH)
except Exception:
    iso_scaler = None

try:
    autoencoder = load_model(AE_MODEL_PATH, compile=False)
except Exception as e:
    raise RuntimeError(f"Failed to load Autoencoder model: {e}")

try:
    ae_scaler = joblib.load(AE_SCALER_PATH)
except Exception:
    ae_scaler = None

# --------------------------------------------------
# HYBRID PARAMETERS
# --------------------------------------------------
RULE_WEIGHT = 0.4
ML_WEIGHT = 0.6

ISO_WEIGHT = 0.5
AE_WEIGHT = 0.5

MODERATE_THRESHOLD = 0.35
ANOMALY_THRESHOLD = 0.70

# --------------------------------------------------
# FEATURE BUILDER
# --------------------------------------------------
def _ensure_features_df(
    current_txn: dict,
    last_txn: Optional[dict],
    feature_names: List[str],
) -> pd.DataFrame:

    txn_time = current_txn.get("transaction_date", datetime.utcnow())
    last_time = last_txn.get("transaction_date") if last_txn else None

    time_since_last = (
        (txn_time - last_time).total_seconds()
        if last_time and isinstance(last_time, datetime)
        else 86400.0
    )

    base_map = {
        "TransactionAmount": float(current_txn.get("amount", 0.0)),
        "hour": txn_time.hour,
        "day_of_week": txn_time.weekday(),
        "day": txn_time.day,
        "time_since_last": time_since_last,
        "tx_last_1hr": current_txn.get("tx_last_1hr", 0.0),
        "tx_last_24hr": current_txn.get("tx_last_24hr", 0.0),
        "amount_zscore": current_txn.get("amount_zscore", 0.0),
        "amount_to_balance": current_txn.get("amount_to_balance", 0.0),
        "category_usage_ratio": current_txn.get("category_usage_ratio", 0.0),
        "new_category_flag": current_txn.get("new_category_flag", 0),
        "category_amount_zscore": current_txn.get("category_amount_zscore", 0.0),
        "unique_category_count": current_txn.get("unique_category_count", 0.0),
        "high_risk_category": current_txn.get("high_risk_category", 0),
        "device_changed": current_txn.get("device_changed", 0),
        "ip_changed": current_txn.get("ip_changed", 0),
        "location_changed": current_txn.get("location_changed", 0),
        "LoginAttempts": current_txn.get("login_attempts", 0),
        "AccountBalance": current_txn.get("account_balance", 0.0),
    }

    features = {name: base_map.get(name, 0.0) for name in feature_names}
    return pd.DataFrame([features])

# --------------------------------------------------
# MAIN HYBRID DECISION FUNCTION
# --------------------------------------------------
def hybrid_transaction_decision(
    current_txn: dict,
    last_txn: Optional[dict] = None,
) -> Dict[str, Any]:

    reasons: List[Dict[str, Any]] = []

    # ================= RULE-BASED =================
    rule_out = compute_rule_based_score(current_txn, last_txn)
    total_rule_score = rule_out.get("total_score", 0)
    rule_results = rule_out.get("rule_results", {})

    rule_flag = 1 if total_rule_score >= 40 else 0
    rule_score = min(total_rule_score / 100.0, 1.0)

    for rule_name, result in rule_results.items():
        if result.get("score", 0) > 0:
            reasons.append({
                "source": "rule",
                "code": rule_name.upper(),
                "message": result.get("message", "Rule triggered"),
                "severity": "medium" if result["score"] < 70 else "high",
            })

    # ================= ML (ISOLATION FOREST) =================
    iso_features = (
        list(iso_scaler.feature_names_in_)
        if iso_scaler and hasattr(iso_scaler, "feature_names_in_")
        else list(_ensure_features_df(current_txn, last_txn, []).columns)
    )

    features_df = _ensure_features_df(current_txn, last_txn, iso_features)

    X_iso = (
        iso_scaler.transform(features_df[iso_features])
        if iso_scaler
        else features_df[iso_features].values
    )

    iso_raw = isolation_forest.decision_function(X_iso)[0]
    ml_iso_score = max(0.0, min((-iso_raw + 0.5), 1.0))

    if ml_iso_score > 0.6:
        reasons.append({
            "source": "ml",
            "code": "ISO_ANOMALY",
            "message": "Unusual transaction pattern detected compared to historical behavior.",
            "severity": "high",
        })

    # ================= ML (AUTOENCODER) =================
    ae_features = (
        list(ae_scaler.feature_names_in_)
        if ae_scaler and hasattr(ae_scaler, "feature_names_in_")
        else iso_features
    )

    ae_df = _ensure_features_df(current_txn, last_txn, ae_features)

    X_ae = (
        ae_scaler.transform(ae_df[ae_features])
        if ae_scaler
        else ae_df[ae_features].values
    )

    recon = autoencoder.predict(X_ae, verbose=0)
    mse = np.mean(np.square(X_ae - recon), axis=1)[0]

    ml_ae_score = 1.0 - np.exp(-mse / 1e-3)
    ml_ae_score = max(0.0, min(ml_ae_score, 1.0))

    if ml_ae_score > 0.6:
        reasons.append({
            "source": "ml",
            "code": "AE_RECON_ERROR",
            "message": "Autoencoder reconstruction error indicates abnormal behavior.",
            "severity": "high",
        })

    # ================= SCORE FUSION =================
    ml_score = (ISO_WEIGHT * ml_iso_score) + (AE_WEIGHT * ml_ae_score)
    hybrid_score = (RULE_WEIGHT * rule_score) + (ML_WEIGHT * ml_score)

    if hybrid_score >= ANOMALY_THRESHOLD:
        severity = "high"
        is_anomaly = 1
        is_moderate = 0
    elif hybrid_score >= MODERATE_THRESHOLD:
        severity = "moderate"
        is_anomaly = 0
        is_moderate = 1
    else:
        severity = "normal"
        is_anomaly = 0
        is_moderate = 0

    if not reasons and severity != "normal":
        reasons.append({
            "source": "hybrid",
            "code": "COMBINED_RISK",
            "message": "Multiple weak signals combined into elevated risk.",
            "severity": severity,
        })

    reason_summary = "; ".join(r["message"] for r in reasons) if reasons else "No risk detected."

    # # Rule-based reasons
    # for rule_name, result in rule_results.items():
    #  if result.get("score", 0) > 0:
    #     reasons.append({
    #         "source": "rule",
    #         "code": rule_name.upper(),
    #         "message": result["message"],
    #         "severity": "high" if result["score"] >= 40 else "medium"
    #     })


    # ================= FINAL RESPONSE =================
    return {
        "event_type": "transaction",
        "rule_flag": rule_flag,
        "rule_score": round(rule_score, 4),
        "rule_details": rule_results,
        "ml_iso_score": round(ml_iso_score, 4),
        "ml_ae_score": round(ml_ae_score, 4),
        "ml_score": round(ml_score, 4),
        "hybrid_score": round(hybrid_score, 4),
        "is_moderate": is_moderate,
        "is_anomaly": is_anomaly,
        "severity": severity,
        "reasons": reasons,
        "reason_summary": reason_summary,
    }