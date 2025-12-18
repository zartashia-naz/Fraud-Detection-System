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

from app.core.transaction_rule_based import compute_rule_based_score

# Deep learning imports
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
# Load with failsafe messages to aid debugging when running tests
try:
    isolation_forest = joblib.load(ISO_MODEL_PATH)
except Exception as e:
    raise RuntimeError(f"Failed to load Isolation Forest model: {ISO_MODEL_PATH}: {e}")

try:
    iso_scaler = joblib.load(ISO_SCALER_PATH)
except Exception:
    iso_scaler = None

try:
    autoencoder = load_model(AE_MODEL_PATH, compile=False)
except Exception as e:
    raise RuntimeError(f"Failed to load Autoencoder model: {AE_MODEL_PATH}: {e}")

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


def _ensure_features_df(current_txn: dict, last_txn: dict | None, feature_names: list) -> pd.DataFrame:
    """Create a single-row features DataFrame required by scalers/models.

    If certain features are missing, reasonable defaults are used so the
    pipeline can still run for integration and testing purposes.
    """
    txn_time = current_txn.get("transaction_date") or datetime.utcnow()
    last_time = last_txn.get("transaction_date") if last_txn else None

    time_since_last = (
        (txn_time - last_time).total_seconds() if last_time and isinstance(last_time, datetime) else 86400.0
    )

    device_changed = 1 if last_txn and current_txn.get("device_id") != last_txn.get("device_id") else 0
    ip_changed = 1 if last_txn and current_txn.get("ip") != last_txn.get("ip") else 0
    location_changed = 1 if last_txn and current_txn.get("location", {}).get("city") != last_txn.get("location", {}).get("city") else 0

    base_map = {
        "TransactionAmount": float(current_txn.get("amount", 0.0)),
        "hour": int(txn_time.hour),
        "day_of_week": int(txn_time.weekday()),
        "day": int(txn_time.day),
        "time_since_last": float(time_since_last),
        "tx_last_1hr": float(current_txn.get("tx_last_1hr", 0.0)),
        "tx_last_24hr": float(current_txn.get("tx_last_24hr", 0.0)),
        "amount_zscore": float(current_txn.get("amount_zscore", 0.0)),
        "amount_to_balance": float(current_txn.get("amount_to_balance", 0.0)),
        "category_usage_ratio": float(current_txn.get("category_usage_ratio", 0.0)),
        "new_category_flag": int(current_txn.get("new_category_flag", 0)),
        "category_amount_zscore": float(current_txn.get("category_amount_zscore", 0.0)),
        "unique_category_count": float(current_txn.get("unique_category_count", 0.0)),
        "high_risk_category": int(current_txn.get("high_risk_category", 0)),
        "device_changed": int(device_changed),
        "ip_changed": int(ip_changed),
        "location_changed": int(location_changed),
        "LoginAttempts": int(current_txn.get("login_attempts", 0)),
        "AccountBalance": float(current_txn.get("account_balance", 0.0)),
    }

    features = {}
    for name in feature_names:
        if name in base_map:
            features[name] = base_map[name]
        else:
            features[name] = 0.0

    return pd.DataFrame([features])


def hybrid_transaction_decision(current_txn: dict, last_txn: dict | None = None) -> dict:
    """Run hybrid transaction anomaly decision.

    Returns a dict containing rule and ML scores and final hybrid decision.
    """
    # 1. Rule-based
    rule_out = compute_rule_based_score(current_txn, last_txn)
    total_rule_score = rule_out.get("total_score", 0)
    rule_results = rule_out.get("rule_results", {})

    rule_flag = 1 if total_rule_score >= 40 else 0
    rule_score = float(min(total_rule_score / 100.0, 1.0))

    # 2. ML-based
    # Determine feature names – **always prefer the IsolationForest spec**
    # to avoid dimension mismatches between scaler and model.
    iso_features = None

    # (a) If the IsolationForest was trained with named columns, use that list.
    if hasattr(isolation_forest, "feature_names_in_"):
        iso_features = list(isolation_forest.feature_names_in_)

    # (b) Otherwise, fall back to scaler feature names (if available).
    if iso_features is None and iso_scaler is not None and hasattr(iso_scaler, "feature_names_in_"):
        iso_features = list(iso_scaler.feature_names_in_)

    # (c) Final fallback: hard-coded list used during training.
    if iso_features is None:
        iso_features = [
            "TransactionAmount", "hour", "day_of_week", "day", "time_since_last",
            "tx_last_1hr", "tx_last_24hr", "amount_zscore", "amount_to_balance",
            "category_usage_ratio", "new_category_flag", "category_amount_zscore",
            "unique_category_count", "high_risk_category", "device_changed",
            "ip_changed", "location_changed", "LoginAttempts", "AccountBalance",
        ]

    features_df = _ensure_features_df(current_txn, last_txn, iso_features)

    # Use the scaler **only if** its expected feature count matches the model.
    use_scaler = (
        iso_scaler is not None
        and hasattr(iso_scaler, "n_features_in_")
        and iso_scaler.n_features_in_ == len(iso_features)
    )

    try:
        if use_scaler:
            X_iso = iso_scaler.transform(features_df[iso_features])
        else:
            X_iso = features_df[iso_features].values
    except Exception:
        X_iso = features_df[iso_features].values

    iso_raw = isolation_forest.decision_function(X_iso)[0]
    ml_iso_raw = -iso_raw
    ml_iso_score = (ml_iso_raw + 0.5) / 1.0
    ml_iso_score = max(0.0, min(ml_iso_score, 1.0))

    # Autoencoder
    ae_feature_names = None
    if ae_scaler is not None and hasattr(ae_scaler, "feature_names_in_"):
        ae_feature_names = list(ae_scaler.feature_names_in_)
    if not ae_feature_names:
        ae_feature_names = iso_features

    ae_df = _ensure_features_df(current_txn, last_txn, ae_feature_names)

    try:
        X_ae = ae_scaler.transform(ae_df[ae_feature_names]) if ae_scaler is not None else ae_df[ae_feature_names].values
    except Exception:
        X_ae = ae_df[ae_feature_names].values

    recon = autoencoder.predict(X_ae, verbose=0)
    mse = np.mean(np.square(X_ae - recon), axis=1)[0]

    AE_SCALE = 1e-3
    ml_ae_score = 1.0 - float(np.exp(-mse / AE_SCALE))
    ml_ae_score = max(0.0, min(ml_ae_score, 1.0))

    ml_score = (ISO_WEIGHT * ml_iso_score) + (AE_WEIGHT * ml_ae_score)

    # 3. Fusion
    hybrid_score = (RULE_WEIGHT * rule_score) + (ML_WEIGHT * ml_score)

    if hybrid_score >= ANOMALY_THRESHOLD:
        is_anomaly = 1
        is_moderate = 0
    elif hybrid_score >= MODERATE_THRESHOLD:
        is_anomaly = 0
        is_moderate = 1
    else:
        is_anomaly = 0
        is_moderate = 0

    return {
        "event_type": "transaction",
        "rule_flag": int(rule_flag),
        "rule_score": round(float(rule_score), 4),
        "rule_details": rule_results,
        "ml_iso_score": round(float(ml_iso_score), 4),
        "ml_ae_score": round(float(ml_ae_score), 4),
        "ml_score": round(float(ml_score), 4),
        "hybrid_score": round(float(hybrid_score), 4),
        "is_moderate": int(is_moderate),
        "is_anomaly": int(is_anomaly),
    }
