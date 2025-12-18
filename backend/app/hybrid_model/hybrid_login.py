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

MODERATE_THRESHOLD = 0.35   # ⚠️ monitor / step-up auth
ANOMALY_THRESHOLD  = 0.70   # 🚨 block / alert



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
        Hybrid login anomaly result
    """

    # -------------------------------
    # 1. RULE-BASED DETECTION
    # -------------------------------
    rule_flag = login_rule_engine(login_event_df)

    rule_score = 1.0 if rule_flag == 1 else 0.0

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

    # Isolation Forest: lower decision_function value = more anomalous
    # decision_function returns: negative for outliers, positive for inliers
    ml_raw_score = isolation_forest.decision_function(X_combined)[0]
    
    # Convert to anomaly score: more negative = more anomalous
    # Typical range: [-0.5, 0.5], but can vary
    # Normalize: shift and scale to [0, 1] where 1 = most anomalous
    # Using sigmoid-like transformation or percentile-based normalization
    # For Isolation Forest: negative scores indicate anomalies
    ml_anomaly_score = -ml_raw_score  # Negate so positive = anomalous
    
    # Normalize to [0, 1] range
    # Assuming typical range [-0.5, 0.5], map to [0, 1]
    # Use tanh-based normalization or percentile clipping
    ml_score = (ml_anomaly_score + 0.5) / 1.0  # Simple linear scaling
    ml_score = max(0.0, min(ml_score, 1.0))  # Clip to [0, 1]

    # -------------------------------
    # 3. HYBRID FUSION
    # -------------------------------
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
    
    # -------------------------------
    # 4. OUTPUT
    # -------------------------------
    return {
        "event_type": "login",
        "rule_flag": rule_flag,
        "rule_score": round(rule_score, 4),
        "ml_score": round(ml_score, 4),
        "hybrid_score": round(hybrid_score, 4),
        "is_moderate": is_moderate,
        "is_anomaly": is_anomaly
    }


# # --------------------------------------------------
# # OPTIONAL: QUICK TEST BLOCK
# # --------------------------------------------------

# if __name__ == "__main__":
#     print("=" * 80)
#     print("HYBRID LOGIN ANOMALY DETECTION - TEST CASES")
#     print("=" * 80)
#     print()
    
#     # Test Case 1: NORMAL LOGIN (should not be flagged as anomaly)
#     print("-" * 80)
#     print("CASE 1: NORMAL LOGIN")
#     print("-" * 80)
#     normal_login = pd.DataFrame([{
#         "login_hour": 14,  # 2 PM - normal time
#         "login_dayofweek": 2,  # Wednesday
#         "is_weekend": 0,
#         "time_since_last_login": 3600.0,  # 1 hour ago - normal
#         "device_changed": 0,  # Same device
#         "ip_changed": 0,  # Same IP
#         "location_changed": 0,  # Same location
#         "LoginAttempts": 1,  # Single successful attempt
#         "failed_login": 0,
#         "high_login_attempts": 0
#     }])
#     result1 = hybrid_login_decision(normal_login)
#     print(f"Result: {result1}")
#     print(f"Detailed Analysis:")
#     print(f"  - Rule-based flag: {result1['rule_flag']} ({'Anomaly' if result1['rule_flag'] == 1 else 'Normal'})")
#     print(f"  - Rule-based score: {result1['rule_score']}")
#     print(f"  - ML-based score: {result1['ml_score']}")
#     print(f"  - Hybrid score: {result1['hybrid_score']} (threshold: {ANOMALY_THRESHOLD})")
#     print(f"  - Final Decision: {'ANOMALY DETECTED' if result1['is_anomaly'] == 1 else 'NORMAL LOGIN'}")
#     print()
    
#     # Test Case 2: SUSPICIOUS LOGIN (should be flagged as anomaly)
#     print("-" * 80)
#     print("CASE 2: SUSPICIOUS LOGIN (Multiple Red Flags)")
#     print("-" * 80)
#     suspicious_login = pd.DataFrame([{
#         "login_hour": 3,  # 3 AM - unusual time
#         "login_dayofweek": 6,  # Saturday
#         "is_weekend": 1,
#         "time_since_last_login": 100.0,  # Very recent (suspicious)
#         "device_changed": 1,  # New device
#         "ip_changed": 1,  # New IP
#         "location_changed": 1,  # New location
#         "LoginAttempts": 8,  # High number of attempts
#         "failed_login": 1,  # Failed login
#         "high_login_attempts": 1  # High attempts flag
#     }])
#     result2 = hybrid_login_decision(suspicious_login)
#     print(f"Result: {result2}")
#     print(f"Detailed Analysis:")
#     print(f"  - Rule-based flag: {result2['rule_flag']} ({'Anomaly' if result2['rule_flag'] == 1 else 'Normal'})")
#     print(f"  - Rule-based score: {result2['rule_score']}")
#     print(f"  - ML-based score: {result2['ml_score']}")
#     print(f"  - Hybrid score: {result2['hybrid_score']} (threshold: {ANOMALY_THRESHOLD})")
#     print(f"  - Final Decision: {'ANOMALY DETECTED' if result2['is_anomaly'] == 1 else 'NORMAL LOGIN'}")
#     print()
    
#     # Test Case 3: ANOMALY CASE (should be flagged - extreme values)
#     print("-" * 80)
#     print("CASE 3: ANOMALY DETECTED (Extreme Suspicion)")
#     print("-" * 80)
#     anomaly_login = pd.DataFrame([{
#         "login_hour": 1,  # 1 AM - very unusual time
#         "login_dayofweek": 6,  # Saturday
#         "is_weekend": 1,
#         "time_since_last_login": 10.0,  # Very recent (10 seconds) - highly suspicious
#         "device_changed": 1,  # New device
#         "ip_changed": 1,  # New IP
#         "location_changed": 1,  # New location
#         "LoginAttempts": 15,  # Very high attempts
#         "failed_login": 1,  # Failed login
#         "high_login_attempts": 1  # High attempts flag
#     }])
#     result3 = hybrid_login_decision(anomaly_login)
#     print(f"Result: {result3}")
#     print(f"Detailed Analysis:")
#     print(f"  - Rule-based flag: {result3['rule_flag']} ({'Anomaly' if result3['rule_flag'] == 1 else 'Normal'})")
#     print(f"  - Rule-based score: {result3['rule_score']}")
#     print(f"  - ML-based score: {result3['ml_score']}")
#     print(f"  - Hybrid score: {result3['hybrid_score']} (threshold: {ANOMALY_THRESHOLD})")
#     print(f"  - Final Decision: {'ANOMALY DETECTED' if result3['is_anomaly'] == 1 else 'NORMAL LOGIN'}")
#     print()
    
#     # Test Case 4: VERY LOW ANOMALY (minimal suspicious indicators)
#     print("-" * 80)
#     print("CASE 4: VERY LOW ANOMALY (Minimal Suspicious Indicators)")
#     print("-" * 80)
#     low_anomaly_login = pd.DataFrame([{
#         "login_hour": 1,  # 1 AM - unusual hour (triggers rule)
#         "login_dayofweek": 2,  # Wednesday
#         "is_weekend": 0,
#         "time_since_last_login": 3600.0,  # 1 hour ago - normal
#         "device_changed": 0,  # Same device
#         "ip_changed": 0,  # Same IP
#         "location_changed": 0,  # Same location
#         "LoginAttempts": 2,  # Normal attempts (below threshold)
#         "failed_login": 0,  # No failures
#         "high_login_attempts": 0  # Normal attempts
#     }])
#     result4 = hybrid_login_decision(low_anomaly_login)
#     print(f"Result: {result4}")
#     print(f"Detailed Analysis:")
#     print(f"  - Rule-based flag: {result4['rule_flag']} ({'Anomaly' if result4['rule_flag'] == 1 else 'Normal'})")
#     print(f"  - Rule-based score: {result4['rule_score']}")
#     print(f"  - ML-based score: {result4['ml_score']}")
#     print(f"  - Hybrid score: {result4['hybrid_score']} (threshold: {ANOMALY_THRESHOLD})")
#     print(f"  - Final Decision: {'ANOMALY DETECTED' if result4['is_anomaly'] == 1 else 'NORMAL LOGIN'}")
#     print()
    
#     print("=" * 80)
#     print("SUMMARY")
#     print("=" * 80)
#     print(f"Case 1 (Normal):      {'ANOMALY' if result1['is_anomaly'] == 1 else 'NORMAL'} - Hybrid Score: {result1['hybrid_score']:.4f} | Rule: {result1['rule_score']:.2f} | ML: {result1['ml_score']:.4f}")
#     print(f"Case 2 (Suspicious):  {'ANOMALY' if result2['is_anomaly'] == 1 else 'NORMAL'} - Hybrid Score: {result2['hybrid_score']:.4f} | Rule: {result2['rule_score']:.2f} | ML: {result2['ml_score']:.4f}")
#     print(f"Case 3 (Anomaly):     {'ANOMALY' if result3['is_anomaly'] == 1 else 'NORMAL'} - Hybrid Score: {result3['hybrid_score']:.4f} | Rule: {result3['rule_score']:.2f} | ML: {result3['ml_score']:.4f}")
#     print(f"Case 4 (Very Low):    {'ANOMALY' if result4['is_anomaly'] == 1 else 'NORMAL'} - Hybrid Score: {result4['hybrid_score']:.4f} | Rule: {result4['rule_score']:.2f} | ML: {result4['ml_score']:.4f}")
    
#     # Test Case 5: MODERATE ANOMALY (targeting ~0.4 score)
#     # Note: Getting exactly 0.4 is challenging because:
#     # - If rule_flag=0: Need ML score = 0.6667 (very high, ML typically scores 0.3-0.4)
#     # - If rule_flag=1: Minimum hybrid score = 0.5 (from rule weight alone)
#     # This case demonstrates the closest achievable score with rule_flag=0
#     print("-" * 80)
#     print("CASE 5: MODERATE ANOMALY (Targeting ~0.4 Hybrid Score)")
#     print("-" * 80)
#     # Target: hybrid_score = 0.4
#     # Formula: (0.5 * rule_score) + (0.6 * ml_score) = 0.4
#     # If rule_score = 0: ml_score = 0.4/0.6 = 0.6667
#     # If rule_score = 1: ml_score = (0.4 - 0.5)/0.6 = negative (impossible)
#     # So we need rule_flag = 0 and ml_score ≈ 0.67
#     # To get higher ML score, we need more unusual patterns but not enough to trigger rule-based
#     moderate_04_login = pd.DataFrame([{
#         "login_hour": 1,  # 1 AM - very unusual hour (25 points - single indicator only, < 40 threshold)
#         "login_dayofweek": 6,  # Sunday
#         "is_weekend": 1,
#         "time_since_last_login": 120.0,  # 2 minutes - very recent but above 60s threshold
#         "device_changed": 0,  # Same device (avoid adding more rule points)
#         "ip_changed": 0,  # Same IP
#         "location_changed": 0,  # Same location
#         "LoginAttempts": 4,  # Slightly elevated but not > 3 for rule (wait, > 3 should trigger... let me check)
#         "failed_login": 1,  # Failed login (35 points - but this alone is < 40, so rule_flag should still be 0...)
#         "high_login_attempts": 1  # This would trigger high_login_attempts rule
#     }])
    
#     # Actually, to get exactly 0.4, we need rule_flag = 0 and ml_score = 0.6667
#     # But ML model rarely scores that high. Let's try with just unusual hour
#     moderate_04_login = pd.DataFrame([{
#         "login_hour": 0,  # Midnight - most unusual hour (25 points - single indicator, < 40)
#         "login_dayofweek": 4,  # Friday
#         "is_weekend": 0,
#         "time_since_last_login": 200.0,  # ~3 minutes - recent but above rapid threshold
#         "device_changed": 0,  # Same device
#         "ip_changed": 0,  # Same IP  
#         "location_changed": 0,  # Same location
#         "LoginAttempts": 2,  # Normal attempts
#         "failed_login": 0,  # No failures
#         "high_login_attempts": 0  # Normal attempts
#     }])
#     result5 = hybrid_login_decision(moderate_04_login)
#     print(f"Result: {result5}")
#     print(f"Detailed Analysis:")
#     print(f"  - Rule-based flag: {result5['rule_flag']} ({'Anomaly' if result5['rule_flag'] == 1 else 'Normal'})")
#     print(f"  - Rule-based score: {result5['rule_score']}")
#     print(f"  - ML-based score: {result5['ml_score']:.4f}")
#     print(f"  - Hybrid score: {result5['hybrid_score']:.4f} (target: ~0.4, moderate threshold: {MODERATE_THRESHOLD}, anomaly threshold: {ANOMALY_THRESHOLD})")
#     print(f"  - Final Decision: {'ANOMALY DETECTED' if result5['is_anomaly'] == 1 else 'MODERATE SUSPICION' if result5['is_moderate'] == 1 else 'NORMAL LOGIN'}")
#     if 0.38 <= result5['hybrid_score'] <= 0.42:
#         print(f"  - ✅ Target achieved: Score is approximately 0.4!")
#     print()
    
#     print("=" * 80)
#     print("SUMMARY")
#     print("=" * 80)
#     print(f"Case 1 (Normal):      {'ANOMALY' if result1['is_anomaly'] == 1 else 'NORMAL'} - Hybrid Score: {result1['hybrid_score']:.4f} | Rule: {result1['rule_score']:.2f} | ML: {result1['ml_score']:.4f}")
#     print(f"Case 2 (Suspicious):  {'ANOMALY' if result2['is_anomaly'] == 1 else 'NORMAL'} - Hybrid Score: {result2['hybrid_score']:.4f} | Rule: {result2['rule_score']:.2f} | ML: {result2['ml_score']:.4f}")
#     print(f"Case 3 (Anomaly):     {'ANOMALY' if result3['is_anomaly'] == 1 else 'NORMAL'} - Hybrid Score: {result3['hybrid_score']:.4f} | Rule: {result3['rule_score']:.2f} | ML: {result3['ml_score']:.4f}")
#     print(f"Case 4 (Very Low):    {'ANOMALY' if result4['is_anomaly'] == 1 else 'NORMAL'} - Hybrid Score: {result4['hybrid_score']:.4f} | Rule: {result4['rule_score']:.2f} | ML: {result4['ml_score']:.4f}")
#     print(f"Case 5 (Moderate 0.4): {'ANOMALY' if result5['is_anomaly'] == 1 else 'MODERATE' if result5['is_moderate'] == 1 else 'NORMAL'} - Hybrid Score: {result5['hybrid_score']:.4f} | Rule: {result5['rule_score']:.2f} | ML: {result5['ml_score']:.4f}")
#     print("=" * 80)



#     # -------------------------------
# # 4️⃣ MODERATE SUSPICION LOGIN
# # -------------------------------

# moderate_suspicion = pd.DataFrame([{
#     "login_hour": 22,                 # Late-night login
#     "login_dayofweek": 5,             # Saturday
#     "is_weekend": 1,                  # Weekend
#     "time_since_last_login": 900,     # 15 minutes
#     "device_changed": 0,              # Same device
#     "ip_changed": 1,                  # New IP
#     "location_changed": 0,            # Same location
#     "LoginAttempts": 4,               # Slightly elevated
#     "failed_login": 1,                # One failure
#     "high_login_attempts": 0          # Below rule threshold
# }])

# print("MODERATE SUSPICION LOGIN:")
# print(hybrid_login_decision(moderate_suspicion), "\n")
