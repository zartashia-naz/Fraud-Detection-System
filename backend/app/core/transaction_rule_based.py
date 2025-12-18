# app/core/anomaly/rule_based.py
from datetime import datetime

# ----------------------------------------------------
# RULE-BASED ENGINE FOR TRANSACTION ANOMALY SCORE
# ----------------------------------------------------
def compute_rule_based_score(current_txn: dict, last_txn: dict | None) -> dict:
    """
    Calculates rule-based anomaly score using fast DSA rules.
    Returns:
        total_score: combined anomaly score
        rule_results: {rule_name: {"score": int, "message": str}}
    """
    # ------------------------------------------
    # RULE DEFINITIONS (DSA-FRIENDLY)
    # ------------------------------------------
    RULES = {
        "device_change": {
            "weight": 20,
            "message": "Transaction made from a new or unusual device."
        },
        "ip_change": {
            "weight": 25,
            "message": "IP address changed from last known IP."
        },
        "city_change": {
            "weight": 20,
            "message": "Transaction performed from a new city."
        },
        "country_change": {
            "weight": 30,
            "message": "Transaction originated from a different country."
        },
        "transaction_duration": {
            "weight": 15,
            "message": "Two transactions made too quickly, suspicious rapid activity."
        },
        "midnight_transaction": {
            "weight": 10,
            "message": "Transaction made at unusual time (00:00–04:00)."
        },
    }

    rule_results = {}      # store: rule -> {score, message}
    anomaly_score = 0

    # First transaction cannot be judged
    if last_txn is None:
        return {
            "total_score": 0,
            "rule_results": {},
            "is_first_transaction": True,
            "message": "First transaction — no anomalies evaluated."
        }

    # Extract fields
    new_device = current_txn.get("device_id")
    old_device = last_txn.get("device_id")

    new_ip = current_txn.get("ip")
    old_ip = last_txn.get("ip")

    new_loc = current_txn.get("location", {})
    old_loc = last_txn.get("location", {})

    txn_time = current_txn.get("transaction_date")
    duration = current_txn.get("transaction_duration")  # seconds

    # ---------------------------
    # RULE 1: DEVICE CHANGE
    # ---------------------------
    triggered = new_device != old_device
    score = RULES["device_change"]["weight"] if triggered else 0
    rule_results["device_change"] = {
        "score": score,
        "message": RULES["device_change"]["message"] if triggered else "Device consistent with previous transaction."
    }
    anomaly_score += score

    # ---------------------------
    # RULE 2: IP CHANGE
    # ---------------------------
    triggered = new_ip != old_ip
    score = RULES["ip_change"]["weight"] if triggered else 0
    rule_results["ip_change"] = {
        "score": score,
        "message": RULES["ip_change"]["message"] if triggered else "IP address matches previous transaction."
    }
    anomaly_score += score

    # ---------------------------
    # RULE 3: CITY CHANGE
    # ---------------------------
    triggered = (
        new_loc.get("city") 
        and old_loc.get("city") 
        and new_loc.get("city") != old_loc.get("city")
    )
    score = RULES["city_change"]["weight"] if triggered else 0
    rule_results["city_change"] = {
        "score": score,
        "message": RULES["city_change"]["message"] if triggered else "City remains same as previous transaction."
    }
    anomaly_score += score

    # ---------------------------
    # RULE 4: COUNTRY CHANGE
    # ---------------------------
    triggered = (
        new_loc.get("country") 
        and old_loc.get("country") 
        and new_loc.get("country") != old_loc.get("country")
    )
    score = RULES["country_change"]["weight"] if triggered else 0
    rule_results["country_change"] = {
        "score": score,
        "message": RULES["country_change"]["message"] if triggered else "Country remains same as previous transaction."
    }
    anomaly_score += score

    # ---------------------------
    # RULE 5: VERY SHORT DURATION
    # ---------------------------
    triggered = duration is not None and duration < 15
    score = RULES["transaction_duration"]["weight"] if triggered else 0
    rule_results["transaction_duration"] = {
        "score": score,
        "message": RULES["transaction_duration"]["message"] if triggered else "Transaction timing normal."
    }
    anomaly_score += score

    # ---------------------------
    # RULE 6: MIDNIGHT TIME
    # ---------------------------
    hour = txn_time.hour if isinstance(txn_time, datetime) else 0
    triggered = 0 <= hour <= 4
    score = RULES["midnight_transaction"]["weight"] if triggered else 0
    rule_results["midnight_transaction"] = {
        "score": score,
        "message": RULES["midnight_transaction"]["message"] if triggered else "Transaction time is normal."
    }
    anomaly_score += score

    # ---------------------------
    # FINAL RESULT
    # ---------------------------
    final_message = (
        "Several risk indicators detected." if anomaly_score >= 40 else
        "Minor unusual behavior detected." if anomaly_score > 0 else
        "No anomalies detected."
    )

    return {
        "total_score": anomaly_score,
        "rule_results": rule_results,
        "message": final_message
    }