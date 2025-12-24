# ============================================================================
# FILE 5: backend/app/utils/login_feature_extractor.py (UPDATED)
# ============================================================================

"""
UPDATED: Add trusted device check to login feature extraction
"""

import pandas as pd
from datetime import datetime
from typing import Optional


def extract_login_features(
    current_login: dict,
    previous_login: Optional[dict],
    login_status: str,
    is_device_trusted: bool = False  # ✅ NEW PARAMETER
) -> pd.DataFrame:
    """
    Extract features from login event for anomaly detection.
    
    Parameters
    ----------
    current_login : dict
        Current login information
    previous_login : Optional[dict]
        Previous successful login information
    login_status : str
        Login status (success/failed)
    is_device_trusted : bool
        Whether the device is in trusted devices (NEW)
        
    Returns
    -------
    pd.DataFrame
        Single-row dataframe with extracted features
    """
    
    login_time = current_login.get("login_time", datetime.utcnow())
    
    # Time-based features
    login_hour = login_time.hour
    login_dayofweek = login_time.weekday()
    is_weekend = 1 if login_dayofweek >= 5 else 0
    
    # Time since last login
    time_since_last_login = 0.0
    if previous_login and previous_login.get("login_time"):
        prev_time = previous_login["login_time"]
        time_diff = (login_time - prev_time).total_seconds()
        time_since_last_login = max(0, time_diff)
    else:
        # First login - set to a high value to indicate no history
        time_since_last_login = 86400.0  # 24 hours
    
    # Device change detection
    device_changed = 0
    if previous_login:
        prev_device = previous_login.get("device_id", "")
        curr_device = current_login.get("device_id", "")
        # ✅ UPDATED: Don't flag device change if device is trusted
        if not is_device_trusted and prev_device != curr_device:
            device_changed = 1
    
    # IP change detection
    ip_changed = 0
    if previous_login:
        prev_ip = previous_login.get("ip_address", "")
        curr_ip = current_login.get("ip_address", "")
        if prev_ip != curr_ip:
            ip_changed = 1
    
    # Location change detection
    location_changed = 0
    if previous_login:
        prev_location = previous_login.get("location", {})
        curr_location = current_login.get("location", {})
        
        prev_city = prev_location.get("city", "")
        curr_city = curr_location.get("city", "")
        
        if prev_city != curr_city:
            location_changed = 1
    
    # Login attempts
    login_attempts = current_login.get("login_attempts", 1)
    
    # Failed login flag
    failed_login = 1 if login_status == "failed" else 0
    
    # High login attempts flag (threshold: > 3)
    high_login_attempts = 1 if login_attempts > 3 else 0
    
    # Build feature dataframe
    features = {
        "login_hour": login_hour,
        "login_dayofweek": login_dayofweek,
        "is_weekend": is_weekend,
        "time_since_last_login": time_since_last_login,
        "device_changed": device_changed,  # ✅ This will be 0 if device is trusted
        "ip_changed": ip_changed,
        "location_changed": location_changed,
        "LoginAttempts": login_attempts,
        "failed_login": failed_login,
        "high_login_attempts": high_login_attempts,
        
        # Additional context for anomaly reason building
        "device_id": current_login.get("device_id", ""),
        "device_name": current_login.get("device_name", "Unknown Device"),
        "ip_address": current_login.get("ip_address", ""),
        "location": current_login.get("location", {}),
        "hour": login_hour,  # Alias for compatibility
    }
    
    return pd.DataFrame([features])

