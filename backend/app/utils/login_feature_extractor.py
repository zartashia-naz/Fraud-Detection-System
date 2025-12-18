"""
Login Feature Extractor
-----------------------
Extracts features from login logs for hybrid anomaly detection.

Location:
backend/app/utils/login_feature_extractor.py
"""

import pandas as pd
from datetime import datetime
from typing import Optional, Dict


def extract_login_features(
    current_login: Dict,
    previous_login: Optional[Dict] = None,
    login_status: str = "success"
) -> pd.DataFrame:
    """
    Extracts features from login data for hybrid anomaly detection.
    
    Parameters
    ----------
    current_login : dict
        Current login log data containing:
        - login_time: datetime
        - device_id: str
        - ip_address: str
        - location: dict (with country, city, latitude, longitude)
        - login_attempts: int
    previous_login : dict, optional
        Previous login log data with same structure as current_login
    login_status : str
        Status of login attempt ("success" or "failed")
    
    Returns
    -------
    pd.DataFrame
        Single-row DataFrame with required features for hybrid detection:
        - login_hour: int (0-23)
        - login_dayofweek: int (0-6, Monday=0)
        - is_weekend: int (0 or 1)
        - time_since_last_login: float (seconds)
        - device_changed: int (0 or 1)
        - ip_changed: int (0 or 1)
        - location_changed: int (0 or 1)
        - LoginAttempts: int
        - failed_login: int (0 or 1)
        - high_login_attempts: int (0 or 1)
    """
    
    # Handle login_time - convert to UTC naive datetime if needed
    login_time = current_login.get("login_time")
    if isinstance(login_time, str):
        login_time = datetime.fromisoformat(login_time.replace('Z', '+00:00'))
        # Convert to UTC naive if timezone-aware
        if login_time.tzinfo is not None:
            login_time = login_time.replace(tzinfo=None)
    elif isinstance(login_time, datetime):
        # If timezone-aware, convert to UTC naive
        if login_time.tzinfo is not None:
            login_time = login_time.replace(tzinfo=None)
    else:
        login_time = datetime.utcnow()
    
    # -------------------------------
    # TIME FEATURES
    # -------------------------------
    login_hour = login_time.hour
    login_dayofweek = login_time.weekday()  # Monday=0, Sunday=6
    is_weekend = 1 if login_dayofweek in [5, 6] else 0
    
    # -------------------------------
    # TIME SINCE LAST LOGIN
    # -------------------------------
    if previous_login and previous_login.get("login_time"):
        prev_time = previous_login["login_time"]
        if isinstance(prev_time, str):
            prev_time = datetime.fromisoformat(prev_time.replace('Z', '+00:00'))
            if prev_time.tzinfo is not None:
                prev_time = prev_time.replace(tzinfo=None)
        elif isinstance(prev_time, datetime):
            if prev_time.tzinfo is not None:
                prev_time = prev_time.replace(tzinfo=None)
        
        time_diff = (login_time - prev_time).total_seconds()
        # Ensure non-negative and reasonable (handle timezone issues)
        time_since_last_login = max(0.0, time_diff)
    else:
        # First login: use median default (e.g., 24 hours = 86400 seconds)
        time_since_last_login = 86400.0
    
    # -------------------------------
    # DEVICE CHANGE DETECTION
    # -------------------------------
    current_device = current_login.get("device_id", "")
    if previous_login:
        previous_device = previous_login.get("device_id", "")
        device_changed = 1 if current_device != previous_device else 0
    else:
        # First login: no device change
        device_changed = 0
    
    # -------------------------------
    # IP CHANGE DETECTION
    # -------------------------------
    current_ip = current_login.get("ip_address", "")
    if previous_login:
        previous_ip = previous_login.get("ip_address", "")
        ip_changed = 1 if current_ip != previous_ip else 0
    else:
        # First login: no IP change
        ip_changed = 0
    
    # -------------------------------
    # LOCATION CHANGE DETECTION
    # -------------------------------
    current_location = current_login.get("location", {})
    if previous_login:
        previous_location = previous_login.get("location", {})
        
        # Compare location fields (country, city, or coordinates)
        # If any significant field differs, consider it a location change
        if isinstance(current_location, dict) and isinstance(previous_location, dict):
            # Compare country first (most reliable)
            current_country = current_location.get("country", "")
            previous_country = previous_location.get("country", "")
            
            if current_country and previous_country:
                location_changed = 1 if current_country != previous_country else 0
            else:
                # Fallback to city comparison
                current_city = current_location.get("city", "")
                previous_city = previous_location.get("city", "")
                location_changed = 1 if current_city != previous_city else 0
        else:
            location_changed = 0
    else:
        # First login: no location change
        location_changed = 0
    
    # -------------------------------
    # LOGIN ATTEMPTS
    # -------------------------------
    login_attempts = current_login.get("login_attempts", 1)
    
    # -------------------------------
    # FAILED LOGIN FLAG
    # -------------------------------
    failed_login = 1 if login_status.lower() == "failed" else 0
    
    # -------------------------------
    # HIGH LOGIN ATTEMPTS FLAG
    # -------------------------------
    high_login_attempts = 1 if login_attempts > 3 else 0
    
    # -------------------------------
    # CREATE DATAFRAME
    # -------------------------------
    features_df = pd.DataFrame([{
        "login_hour": login_hour,
        "login_dayofweek": login_dayofweek,
        "is_weekend": is_weekend,
        "time_since_last_login": time_since_last_login,
        "device_changed": device_changed,
        "ip_changed": ip_changed,
        "location_changed": location_changed,
        "LoginAttempts": login_attempts,
        "failed_login": failed_login,
        "high_login_attempts": high_login_attempts
    }])
    
    return features_df
