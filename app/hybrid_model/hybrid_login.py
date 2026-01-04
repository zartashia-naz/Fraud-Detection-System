# # claude:
# """
# Hybrid Login Anomaly Detection
# --------------------------------
# Combines:
# 1. Rule-based login detection
# 2. ML-based (Isolation Forest) login anomaly detection

# Location:
# backend/app/hybrid_model/hybrid_login.py
# """

# import os
# import joblib
# import numpy as np
# import pandas as pd

# from app.core.login_rule_based import RuleBasedDetector

# # Instantiate the rule-based detector
# login_rule_engine = RuleBasedDetector()

# # --------------------------------------------------
# # PATH CONFIGURATION
# # --------------------------------------------------

# BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# MODEL_PATH = os.path.join(
#     BASE_DIR,
#     "ml",
#     "Login_pipeline",
#     "login_isolation_forest.pkl"
# )

# SCALER_PATH = os.path.join(
#     BASE_DIR,
#     "ml",
#     "Login_pipeline",
#     "login_event_scaler.pkl"
# )

# # --------------------------------------------------
# # LOAD ML ARTIFACTS
# # --------------------------------------------------

# isolation_forest = joblib.load(MODEL_PATH)
# scaler = joblib.load(SCALER_PATH)

# # --------------------------------------------------
# # HYBRID PARAMETERS
# # --------------------------------------------------

# RULE_WEIGHT = 0.4
# ML_WEIGHT   = 0.6

# MODERATE_THRESHOLD = 0.40   # ⚠️ monitor / step-up auth
# ANOMALY_THRESHOLD  = 0.75   # 🚨 block / alert


# # --------------------------------------------------
# # HYBRID LOGIN DECISION FUNCTION
# # --------------------------------------------------

# def hybrid_login_decision(login_event_df: pd.DataFrame) -> dict:
#     """
#     Parameters
#     ----------
#     login_event_df : pd.DataFrame
#         Single-row dataframe containing login features

#     Returns
#     -------
#     dict
#         Hybrid login anomaly result with concise reason
#     """

#     if login_event_df.empty:
#         return {
#             "event_type": "login",
#             "rule_flag": 0,
#             "rule_score": 0.0,
#             "ml_score": 0.0,
#             "hybrid_score": 0.0,
#             "is_moderate": 0,
#             "is_anomaly": 0,
#             "anomaly_reason": None
#         }
    
#     row = login_event_df.iloc[0]

#     # -------------------------------
#     # 1. RULE-BASED DETECTION
#     # -------------------------------
#     rule_flag = login_rule_engine(login_event_df)
#     rule_score = 1.0 if rule_flag == 1 else 0.0

#     # -------------------------------
#     # 2. ML-BASED DETECTION
#     # -------------------------------
#     # Expected feature order for the model:
#     # login_hour, login_dayofweek, is_weekend, time_since_last_login,
#     # device_changed, ip_changed, location_changed, LoginAttempts,
#     # failed_login, high_login_attempts
    
#     # Columns that need scaling (scaler was trained on these 4)
#     scale_cols = ['login_hour', 'login_dayofweek', 'time_since_last_login', 'LoginAttempts']
#     binary_cols = ['is_weekend', 'device_changed', 'ip_changed', 'location_changed', 
#                    'failed_login', 'high_login_attempts']
    
#     # Ensure all required columns exist
#     required_cols = scale_cols + binary_cols
#     missing_cols = [col for col in required_cols if col not in login_event_df.columns]
#     if missing_cols:
#         raise ValueError(f"Missing required columns: {missing_cols}")
    
#     # Scale only the numerical columns
#     X_scaled_cols = scaler.transform(login_event_df[scale_cols])
    
#     # Combine scaled and binary features in correct order
#     X_combined = np.hstack([
#         X_scaled_cols[:, 0:1],  # login_hour (scaled)
#         X_scaled_cols[:, 1:2],  # login_dayofweek (scaled)
#         login_event_df[['is_weekend']].values,  # is_weekend
#         X_scaled_cols[:, 2:3],  # time_since_last_login (scaled)
#         login_event_df[['device_changed']].values,  # device_changed
#         login_event_df[['ip_changed']].values,  # ip_changed
#         login_event_df[['location_changed']].values,  # location_changed
#         X_scaled_cols[:, 3:4],  # LoginAttempts (scaled)
#         login_event_df[['failed_login']].values,  # failed_login
#         login_event_df[['high_login_attempts']].values  # high_login_attempts
#     ])

#     # Isolation Forest: lower decision_function value = more anomalous
#     # decision_function returns: negative for outliers, positive for inliers
#     ml_raw_score = isolation_forest.decision_function(X_combined)[0]
    
#     # Convert to anomaly score: more negative = more anomalous
#     # Typical range: [-0.5, 0.5], but can vary
#     # Normalize: shift and scale to [0, 1] where 1 = most anomalous
#     # Using sigmoid-like transformation or percentile-based normalization
#     # For Isolation Forest: negative scores indicate anomalies
#     ml_anomaly_score = -ml_raw_score  # Negate so positive = anomalous
    
#     # Normalize to [0, 1] range
#     # Assuming typical range [-0.5, 0.5], map to [0, 1]
#     # Use tanh-based normalization or percentile clipping
#     ml_score = (ml_anomaly_score + 0.5) / 1.0  # Simple linear scaling
#     ml_score = max(0.0, min(ml_score, 1.0))  # Clip to [0, 1]

#     # -------------------------------
#     # 3. HYBRID FUSION
#     # -------------------------------
#     hybrid_score = (RULE_WEIGHT * rule_score) + (ML_WEIGHT * ml_score)

#     if hybrid_score >= ANOMALY_THRESHOLD:
#         is_anomaly = 1
#         is_moderate = 0
#     elif hybrid_score >= MODERATE_THRESHOLD:
#         is_anomaly = 0
#         is_moderate = 1
#     else:
#         is_anomaly = 0
#         is_moderate = 0
    
#     # -------------------------------
#     # 4. BUILD CONCISE REASON (only if anomaly/moderate)
#     # -------------------------------
#     anomaly_reason = None
    
#     if is_anomaly or is_moderate:
#         anomaly_reason = _build_anomaly_reason(row)
    
#     # -------------------------------
#     # 5. OUTPUT
#     # -------------------------------
#     return {
#         "event_type": "login",
#         "rule_flag": rule_flag,
#         "rule_score": round(rule_score, 4),
#         "ml_score": round(ml_score, 4),
#         "hybrid_score": round(hybrid_score, 4),
#         "is_moderate": is_moderate,
#         "is_anomaly": is_anomaly,
#         "anomaly_reason": anomaly_reason  # ✅ Concise reason with actual values
#     }


# def _build_anomaly_reason(row: pd.Series) -> str:
#     """
#     Build a concise, human-readable anomaly reason with actual values.
#     Similar to real-world security systems (Google, AWS, etc.)
    
#     Parameters
#     ----------
#     row : pd.Series
#         Single row from login event dataframe
        
#     Returns
#     -------
#     str
#         Concise reason like: "Login from Moscow, Russia (95.142.200.15) using new device iPhone 15 Pro"
#     """
#     reasons = []
    
#     # Priority 1: Location change (highest priority - most critical for security)
#     if row.get('location_changed', 0) == 1:
#         location = row.get('location', {})
#         city = location.get('city', 'Unknown')
#         country = location.get('country', 'Unknown')
#         ip = row.get('ip_address', 'Unknown IP')
#         reasons.append(f"Login from {city}, {country} ({ip})")
    
#     # Priority 2: Device change
#     elif row.get('device_changed', 0) == 1:
#         device_name = row.get('device_name', 'Unknown Device')
#         reasons.append(f"Login from new device: {device_name}")
    
#     # Priority 3: IP change (without location change - same city, different network)
#     elif row.get('ip_changed', 0) == 1:
#         ip = row.get('ip_address', 'Unknown IP')
#         reasons.append(f"Login from new IP address: {ip}")
    
#     # Priority 4: Multiple failed attempts (high security concern)
#     login_attempts = row.get('LoginAttempts', row.get('login_attempts', 0))
#     if row.get('high_login_attempts', 0) == 1 or login_attempts > 5:
#         reasons.append(f"{login_attempts} failed login attempts detected")
    
#     # Priority 5: Failed login (single attempt)
#     elif row.get('failed_login', 0) == 1:
#         reasons.append("Failed login attempt")
    
#     # Priority 6: Unusual hour (lower priority but still relevant)
#     hour = row.get('login_hour', row.get('hour', -1))
#     if 0 <= hour <= 4:
#         # Format hour range for better readability
#         reasons.append(f"Login at unusual hour ({hour}:00-{(hour+1):02d}:00)")
    
#     # Priority 7: Rapid login (may indicate automated attack)
#     time_since = row.get('time_since_last_login', None)
#     if time_since is not None and time_since < 60:
#         reasons.append(f"Rapid login attempt ({int(time_since)}s after previous login)")
    
#     # Combine reasons intelligently
#     if len(reasons) == 0:
#         # Fallback message if ML detected anomaly but no specific rules triggered
#         return "Unusual activity pattern detected"
#     elif len(reasons) == 1:
#         return reasons[0]
#     else:
#         # Combine top 2 most important reasons for context
#         return f"{reasons[0]}; {reasons[1]}"




"""
Hybrid Login Anomaly Detection
--------------------------------
Combines:
1. Rule-based login detection
2. ML-based (Isolation Forest) login anomaly detection

Location:
backend/app/hybrid_model/hybrid_login.py
"""

import os
import joblib
import numpy as np
import pandas as pd

from app.core.login_rule_based import RuleBasedDetector

# Instantiate the rule-based detector
login_rule_engine = RuleBasedDetector()

# --------------------------------------------------
# PATH CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "Login_pipeline",
    "login_isolation_forest.pkl"
)

SCALER_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "Login_pipeline",
    "login_event_scaler.pkl"
)

# --------------------------------------------------
# LOAD ML ARTIFACTS
# --------------------------------------------------

isolation_forest = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# --------------------------------------------------
# HYBRID PARAMETERS
# --------------------------------------------------

RULE_WEIGHT = 0.4
ML_WEIGHT   = 0.6

MODERATE_THRESHOLD = 0.45   # ⚠️ monitor / step-up auth (INCREASED from 0.35)
ANOMALY_THRESHOLD  = 0.75   # 🚨 block / alert (INCREASED from 0.70)


# --------------------------------------------------
# HYBRID LOGIN DECISION FUNCTION
# --------------------------------------------------

def hybrid_login_decision(login_event_df: pd.DataFrame) -> dict:
    """
    Parameters
    ----------
    login_event_df : pd.DataFrame
        Single-row dataframe containing login features

    Returns
    -------
    dict
        Hybrid login anomaly result with concise reason
    """

    if login_event_df.empty:
        return {
            "event_type": "login",
            "rule_flag": 0,
            "rule_score": 0.0,
            "ml_score": 0.0,
            "hybrid_score": 0.0,
            "is_moderate": 0,
            "is_anomaly": 0,
            "anomaly_reason": None
        }
    
    row = login_event_df.iloc[0]

    # ✅ FIX: Don't flag first failed attempt as risky
    login_attempts = row.get('LoginAttempts', row.get('login_attempts', 1))
    failed_login = row.get('failed_login', 0)
    
    if failed_login == 1 and login_attempts <= 1:
        # Override features to be non-risky for first attempt
        login_event_df = login_event_df.copy()  # Don't modify original
        login_event_df.loc[0, 'failed_login'] = 0
        login_event_df.loc[0, 'high_login_attempts'] = 0
        row = login_event_df.iloc[0]  # Update row reference

    # ✅ NEW: Detect impossible travel (location change + rapid login)
    impossible_travel = False
    if row.get('location_changed', 0) == 1 and row.get('time_since_last_login') is not None:
        time_gap = row.get('time_since_last_login', 0)
        # If location changed but login happened within 5 minutes, it's impossible travel
        if time_gap < 300:  # 5 minutes
            impossible_travel = True
            print(f"[IMPOSSIBLE TRAVEL] Location changed within {int(time_gap)}s - physically impossible!")

    # -------------------------------
    # 1. RULE-BASED DETECTION
    # -------------------------------
    rule_flag = login_rule_engine(login_event_df)
    rule_score = 1.0 if rule_flag == 1 else 0.0
    
    # ✅ NEW: Boost rule score for impossible travel
    if impossible_travel:
        # Force rule score to at least 0.8 (high risk)
        rule_score = max(rule_score, 0.8)
        print(f"[RULE OVERRIDE] Impossible travel detected - boosting rule_score to {rule_score}")

    # -------------------------------
    # 2. ML-BASED DETECTION
    # -------------------------------
    # Expected feature order for the model:
    # login_hour, login_dayofweek, is_weekend, time_since_last_login,
    # device_changed, ip_changed, location_changed, LoginAttempts,
    # failed_login, high_login_attempts
    
    # Columns that need scaling (scaler was trained on these 4)
    scale_cols = ['login_hour', 'login_dayofweek', 'time_since_last_login', 'LoginAttempts']
    binary_cols = ['is_weekend', 'device_changed', 'ip_changed', 'location_changed', 
                   'failed_login', 'high_login_attempts']
    
    # Ensure all required columns exist
    required_cols = scale_cols + binary_cols
    missing_cols = [col for col in required_cols if col not in login_event_df.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns: {missing_cols}")
    
    # Scale only the numerical columns
    X_scaled_cols = scaler.transform(login_event_df[scale_cols])
    
    # Combine scaled and binary features in correct order
    X_combined = np.hstack([
        X_scaled_cols[:, 0:1],  # login_hour (scaled)
        X_scaled_cols[:, 1:2],  # login_dayofweek (scaled)
        login_event_df[['is_weekend']].values,  # is_weekend
        X_scaled_cols[:, 2:3],  # time_since_last_login (scaled)
        login_event_df[['device_changed']].values,  # device_changed
        login_event_df[['ip_changed']].values,  # ip_changed
        login_event_df[['location_changed']].values,  # location_changed
        X_scaled_cols[:, 3:4],  # LoginAttempts (scaled)
        login_event_df[['failed_login']].values,  # failed_login
        login_event_df[['high_login_attempts']].values  # high_login_attempts
    ])

    # ✅ FIXED: Better normalization for Isolation Forest
    ml_raw_score = isolation_forest.decision_function(X_combined)[0]
    
    # Use percentile-based clipping (more robust)
    # Typical IF range is [-0.7, 0.7] but varies
    ml_anomaly_score = -ml_raw_score  # Negate so positive = anomalous
    
    # Robust normalization with wider range
    if ml_anomaly_score < -0.5:
        ml_score = 0.0
    elif ml_anomaly_score > 0.5:
        ml_score = 1.0
    else:
        ml_score = (ml_anomaly_score + 0.5) / 1.0  # Map [-0.5, 0.5] to [0, 1]
    
    ml_score = max(0.0, min(ml_score, 1.0))  # Clip to [0, 1]

    # -------------------------------
    # 3. HYBRID FUSION
    # -------------------------------
    hybrid_score = (RULE_WEIGHT * rule_score) + (ML_WEIGHT * ml_score)

    # ✅ NEW: Force high risk for impossible travel
    if impossible_travel:
        # Override to at least high-moderate range
        hybrid_score = max(hybrid_score, 0.65)
        print(f"[HYBRID OVERRIDE] Impossible travel - forcing hybrid_score to {hybrid_score}")

    if hybrid_score >= ANOMALY_THRESHOLD:
        is_anomaly = 1
        is_moderate = 0
    elif hybrid_score >= MODERATE_THRESHOLD:
        is_anomaly = 0
        is_moderate = 1
    else:
        is_anomaly = 0
        is_moderate = 0
    
    # -------------------------------
    # 4. BUILD CONCISE REASON (only if anomaly/moderate)
    # -------------------------------
    anomaly_reason = None
    
    if is_anomaly or is_moderate:
        anomaly_reason = _build_anomaly_reason(row)
    
    # -------------------------------
    # 5. OUTPUT
    # -------------------------------
    return {
        "event_type": "login",
        "rule_flag": rule_flag,
        "rule_score": round(rule_score, 4),
        "ml_score": round(ml_score, 4),
        "hybrid_score": round(hybrid_score, 4),
        "is_moderate": is_moderate,
        "is_anomaly": is_anomaly,
        "anomaly_reason": anomaly_reason  # ✅ Concise reason with actual values
    }


def _build_anomaly_reason(row: pd.Series) -> str:
    """
    Build a concise, human-readable anomaly reason with actual values.
    Similar to real-world security systems (Google, AWS, etc.)
    
    Parameters
    ----------
    row : pd.Series
        Single row from login event dataframe
        
    Returns
    -------
    str
        Concise reason like: "Login from Moscow, Russia (95.142.200.15) using new device iPhone 15 Pro"
    """
    reasons = []
    
    # ✅ NEW: Priority 0 - Impossible travel (HIGHEST PRIORITY)
    time_since = row.get('time_since_last_login', None)
    location_changed = row.get('location_changed', 0)
    if location_changed == 1 and time_since is not None and time_since < 300:
        location = row.get('location', {})
        city = location.get('city', 'Unknown')
        country = location.get('country', 'Unknown')
        minutes = int(time_since / 60)
        seconds = int(time_since % 60)
        time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
        reasons.append(f"Impossible travel: Login from {city}, {country} just {time_str} after previous login")
    
    # Priority 1: Location change (highest priority - most critical for security)
    elif row.get('location_changed', 0) == 1:
        location = row.get('location', {})
        city = location.get('city', 'Unknown')
        country = location.get('country', 'Unknown')
        ip = row.get('ip_address', 'Unknown IP')
        reasons.append(f"Login from {city}, {country} ({ip})")
    
    # Priority 2: Device change
    elif row.get('device_changed', 0) == 1:
        device_name = row.get('device_name', 'Unknown Device')
        reasons.append(f"Login from new device: {device_name}")
    
    # Priority 3: IP change (without location change - same city, different network)
    elif row.get('ip_changed', 0) == 1:
        ip = row.get('ip_address', 'Unknown IP')
        reasons.append(f"Login from new IP address: {ip}")
    
    # Priority 4: Multiple failed attempts (high security concern)
    login_attempts = row.get('LoginAttempts', row.get('login_attempts', 0))
    if row.get('high_login_attempts', 0) == 1 or login_attempts > 5:
        reasons.append(f"{login_attempts} failed login attempts detected")
    
    # Priority 5: Failed login (single attempt) - ✅ UPDATED: Only if > 1 attempt
    elif row.get('failed_login', 0) == 1 and login_attempts > 1:
        reasons.append(f"Failed login attempt (attempt {login_attempts})")
    
    # Priority 6: Unusual hour (lower priority but still relevant)
    hour = row.get('login_hour', row.get('hour', -1))
    if 0 <= hour <= 4:
        # Format hour range for better readability
        reasons.append(f"Login at unusual hour ({hour}:00-{(hour+1):02d}:00)")
    
    # Priority 7: Rapid login (may indicate automated attack) - only if not impossible travel
    if time_since is not None and time_since < 60 and not (location_changed == 1 and time_since < 300):
        reasons.append(f"Rapid login attempt ({int(time_since)}s after previous login)")
    
    # Combine reasons intelligently
    if len(reasons) == 0:
        # Fallback message if ML detected anomaly but no specific rules triggered
        return "Unusual activity pattern detected"
    elif len(reasons) == 1:
        return reasons[0]
    else:
        # Combine top 2 most important reasons for context
        return f"{reasons[0]}; {reasons[1]}"
 