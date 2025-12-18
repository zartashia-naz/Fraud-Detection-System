"""
Login Rule-Based Detector (DSA-Optimized)
------------------------------------------
Detects login anomalies using weighted rule-based scoring with DSA principles.

Location:
backend/app/core/login_rule_based.py

DSA Features:
- Dictionary-based rule storage (O(1) lookup)
- Weighted scoring algorithm
- Efficient data structure for rule evaluation
"""

import pandas as pd


class RuleBasedDetector:
    """
    Rule-based detector for login anomalies using DSA-optimized approach.
    Uses weighted scoring with dictionary-based rule storage for efficient evaluation.
    """
    
    def __init__(self):
        # ------------------------------------------
        # RULE DEFINITIONS (DSA-FRIENDLY)
        # Dictionary structure for O(1) rule lookup
        # ------------------------------------------
        self.RULES = {
            "unusual_hour": {
                "weight": 25,
                "message": "Login attempted during unusual hours (00:00–04:00)."
            },
            "high_login_attempts": {
                "weight": 30,
                "message": "High number of login attempts detected."
            },
            "device_change": {
                "weight": 20,
                "message": "Login from a new or changed device."
            },
            "ip_change": {
                "weight": 25,
                "message": "Login from a different IP address."
            },
            "location_change": {
                "weight": 30,
                "message": "Login from a new or different location."
            },
            "failed_login": {
                "weight": 35,
                "message": "Failed login attempt detected."
            },
            "rapid_login": {
                "weight": 20,
                "message": "Rapid login attempts detected."
            }
        }
        
        # Thresholds for rule evaluation
        self.UNUSUAL_HOUR_MIN = 0  # midnight
        self.UNUSUAL_HOUR_MAX = 4  # 4 AM
        self.HIGH_LOGIN_ATTEMPTS_THRESHOLD = 3
        self.RAPID_LOGIN_THRESHOLD = 60  # seconds
        
        # Anomaly threshold: total score >= this triggers anomaly
        self.ANOMALY_THRESHOLD = 40
        
    def __call__(self, login_event_df: pd.DataFrame) -> int:
        """
        Evaluates login event using DSA-optimized weighted scoring algorithm.
        
        Parameters
        ----------
        login_event_df : pd.DataFrame
            Single-row dataframe containing login features
            
        Returns
        -------
        int
            1 if anomaly detected (score >= threshold), 0 otherwise
        """
        if login_event_df.empty:
            return 0
        
        # Extract event data (single row)
        row = login_event_df.iloc[0]
        
        # Dictionary to store rule evaluation results (efficient lookup)
        rule_results = {}
        total_score = 0
        
        # ---------------------------
        # RULE 1: UNUSUAL HOUR
        # O(1) time complexity
        # ---------------------------
        hour = row.get('login_hour', row.get('hour', -1))
        triggered = self.UNUSUAL_HOUR_MIN <= hour <= self.UNUSUAL_HOUR_MAX if hour >= 0 else False
        score = self.RULES["unusual_hour"]["weight"] if triggered else 0
        rule_results["unusual_hour"] = {
            "score": score,
            "triggered": triggered,
            "message": self.RULES["unusual_hour"]["message"] if triggered else "Login during normal hours."
        }
        total_score += score
        
        # ---------------------------
        # RULE 2: HIGH LOGIN ATTEMPTS
        # ---------------------------
        login_attempts = row.get('LoginAttempts', row.get('login_attempts', 0))
        triggered = login_attempts > self.HIGH_LOGIN_ATTEMPTS_THRESHOLD
        score = self.RULES["high_login_attempts"]["weight"] if triggered else 0
        rule_results["high_login_attempts"] = {
            "score": score,
            "triggered": triggered,
            "message": self.RULES["high_login_attempts"]["message"] if triggered else "Normal number of login attempts."
        }
        total_score += score
        
        # ---------------------------
        # RULE 3: DEVICE CHANGE
        # ---------------------------
        device_change = row.get('device_changed', row.get('device_change', 0))
        triggered = device_change == 1
        score = self.RULES["device_change"]["weight"] if triggered else 0
        rule_results["device_change"] = {
            "score": score,
            "triggered": triggered,
            "message": self.RULES["device_change"]["message"] if triggered else "Same device as previous login."
        }
        total_score += score
        
        # ---------------------------
        # RULE 4: IP CHANGE
        # ---------------------------
        ip_change = row.get('ip_changed', row.get('ip_change', 0))
        triggered = ip_change == 1
        score = self.RULES["ip_change"]["weight"] if triggered else 0
        rule_results["ip_change"] = {
            "score": score,
            "triggered": triggered,
            "message": self.RULES["ip_change"]["message"] if triggered else "Same IP address as previous login."
        }
        total_score += score
        
        # ---------------------------
        # RULE 5: LOCATION CHANGE
        # ---------------------------
        location_change = row.get('location_changed', row.get('location_change', 0))
        triggered = location_change == 1
        score = self.RULES["location_change"]["weight"] if triggered else 0
        rule_results["location_change"] = {
            "score": score,
            "triggered": triggered,
            "message": self.RULES["location_change"]["message"] if triggered else "Same location as previous login."
        }
        total_score += score
        
        # ---------------------------
        # RULE 6: FAILED LOGIN
        # ---------------------------
        failed_login = row.get('failed_login', 0)
        triggered = failed_login == 1
        score = self.RULES["failed_login"]["weight"] if triggered else 0
        rule_results["failed_login"] = {
            "score": score,
            "triggered": triggered,
            "message": self.RULES["failed_login"]["message"] if triggered else "Successful login attempt."
        }
        total_score += score
        
        # ---------------------------
        # RULE 7: RAPID LOGIN (if time_since_last_login available)
        # ---------------------------
        time_since_login = row.get('time_since_last_login', None)
        if time_since_login is not None:
            triggered = time_since_login < self.RAPID_LOGIN_THRESHOLD
            score = self.RULES["rapid_login"]["weight"] if triggered else 0
            rule_results["rapid_login"] = {
                "score": score,
                "triggered": triggered,
                "message": self.RULES["rapid_login"]["message"] if triggered else "Normal time between logins."
            }
            total_score += score
        
        # Decision: Binary return (1 if anomaly, 0 if normal)
        # Uses threshold-based decision algorithm
        is_anomaly = 1 if total_score >= self.ANOMALY_THRESHOLD else 0
        
        return is_anomaly
    
    def get_detailed_score(self, login_event_df: pd.DataFrame) -> dict:
        """
        Extended method to return detailed scoring information (for debugging/analysis).
        Returns full rule evaluation results with scores.
        
        Parameters
        ----------
        login_event_df : pd.DataFrame
            Single-row dataframe containing login features
            
        Returns
        -------
        dict
            Detailed scoring results with all rule evaluations
        """
        if login_event_df.empty:
            return {
                "total_score": 0,
                "rule_results": {},
                "is_anomaly": 0,
                "threshold": self.ANOMALY_THRESHOLD
            }
        
        row = login_event_df.iloc[0]
        rule_results = {}
        total_score = 0
        
        # Apply all rules (same logic as __call__)
        hour = row.get('login_hour', row.get('hour', -1))
        triggered = self.UNUSUAL_HOUR_MIN <= hour <= self.UNUSUAL_HOUR_MAX if hour >= 0 else False
        score = self.RULES["unusual_hour"]["weight"] if triggered else 0
        rule_results["unusual_hour"] = {"score": score, "triggered": triggered, "message": self.RULES["unusual_hour"]["message"] if triggered else "Normal hours."}
        total_score += score
        
        login_attempts = row.get('LoginAttempts', row.get('login_attempts', 0))
        triggered = login_attempts > self.HIGH_LOGIN_ATTEMPTS_THRESHOLD
        score = self.RULES["high_login_attempts"]["weight"] if triggered else 0
        rule_results["high_login_attempts"] = {"score": score, "triggered": triggered, "message": self.RULES["high_login_attempts"]["message"] if triggered else "Normal attempts."}
        total_score += score
        
        device_change = row.get('device_changed', row.get('device_change', 0))
        triggered = device_change == 1
        score = self.RULES["device_change"]["weight"] if triggered else 0
        rule_results["device_change"] = {"score": score, "triggered": triggered, "message": self.RULES["device_change"]["message"] if triggered else "Same device."}
        total_score += score
        
        ip_change = row.get('ip_changed', row.get('ip_change', 0))
        triggered = ip_change == 1
        score = self.RULES["ip_change"]["weight"] if triggered else 0
        rule_results["ip_change"] = {"score": score, "triggered": triggered, "message": self.RULES["ip_change"]["message"] if triggered else "Same IP."}
        total_score += score
        
        location_change = row.get('location_changed', row.get('location_change', 0))
        triggered = location_change == 1
        score = self.RULES["location_change"]["weight"] if triggered else 0
        rule_results["location_change"] = {"score": score, "triggered": triggered, "message": self.RULES["location_change"]["message"] if triggered else "Same location."}
        total_score += score
        
        failed_login = row.get('failed_login', 0)
        triggered = failed_login == 1
        score = self.RULES["failed_login"]["weight"] if triggered else 0
        rule_results["failed_login"] = {"score": score, "triggered": triggered, "message": self.RULES["failed_login"]["message"] if triggered else "Successful login."}
        total_score += score
        
        time_since_login = row.get('time_since_last_login', None)
        if time_since_login is not None:
            triggered = time_since_login < self.RAPID_LOGIN_THRESHOLD
            score = self.RULES["rapid_login"]["weight"] if triggered else 0
            rule_results["rapid_login"] = {"score": score, "triggered": triggered, "message": self.RULES["rapid_login"]["message"] if triggered else "Normal time gap."}
            total_score += score
        
        is_anomaly = 1 if total_score >= self.ANOMALY_THRESHOLD else 0
        
        return {
            "total_score": total_score,
            "rule_results": rule_results,
            "is_anomaly": is_anomaly,
            "threshold": self.ANOMALY_THRESHOLD,
            "message": f"Anomaly detected" if is_anomaly else "Normal login"
        }

