from datetime import datetime
from typing import Dict, Optional

# ----------------------------------------------------
# RULE-BASED ENGINE FOR TRANSACTION ANOMALY SCORE
# ----------------------------------------------------
def compute_rule_based_score(
    current_txn: Dict,
    last_txn: Optional[Dict] = None
) -> Dict:
    """
    Calculates rule-based anomaly score using deterministic rules.
    """

    # ------------------------------------------
    # RULE DEFINITIONS
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
        "high_amount_transaction": {
            "weight": 40,
            "message": "Transaction amount is unusually high compared to past behavior."
        }
    }

    rule_results = {}
    anomaly_score = 0

    # ------------------------------------------
    # FIRST TRANSACTION → NO RULES
    # ------------------------------------------
    if last_txn is None:
        return {
            "total_score": 0,
            "rule_results": {},
            "is_first_transaction": True,
            "message": "First transaction — no anomalies evaluated."
        }

    # ------------------------------------------
    # EXTRACT FIELDS SAFELY
    # ------------------------------------------
    amount = float(current_txn.get("amount", 0))
    prev_amount = float(last_txn.get("amount", 0))

    new_device = current_txn.get("device_id")
    old_device = last_txn.get("device_id")

    new_ip = current_txn.get("ip")
    old_ip = last_txn.get("ip")

    new_loc = current_txn.get("location") or {}
    old_loc = last_txn.get("location") or {}

    txn_time = current_txn.get("transaction_date")
    duration = current_txn.get("transaction_duration")

    # ------------------------------------------
    # RULE 1: DEVICE CHANGE
    # ------------------------------------------
    triggered = new_device != old_device
    score = RULES["device_change"]["weight"] if triggered else 0
    rule_results["device_change"] = {
        "score": score,
        "message": RULES["device_change"]["message"]
        if triggered else "Device consistent with previous transaction."
    }
    anomaly_score += score

    # ------------------------------------------
    # RULE 2: IP CHANGE
    # ------------------------------------------
    triggered = new_ip != old_ip
    score = RULES["ip_change"]["weight"] if triggered else 0
    rule_results["ip_change"] = {
        "score": score,
        "message": RULES["ip_change"]["message"]
        if triggered else "IP address matches previous transaction."
    }
    anomaly_score += score

    # ------------------------------------------
    # RULE 3: CITY CHANGE
    # ------------------------------------------
    triggered = (
        new_loc.get("city")
        and old_loc.get("city")
        and new_loc.get("city") != old_loc.get("city")
    )
    score = RULES["city_change"]["weight"] if triggered else 0
    rule_results["city_change"] = {
        "score": score,
        "message": RULES["city_change"]["message"]
        if triggered else "City remains same as previous transaction."
    }
    anomaly_score += score

    # ------------------------------------------
    # RULE 4: COUNTRY CHANGE
    # ------------------------------------------
    triggered = (
        new_loc.get("country")
        and old_loc.get("country")
        and new_loc.get("country") != old_loc.get("country")
    )
    score = RULES["country_change"]["weight"] if triggered else 0
    rule_results["country_change"] = {
        "score": score,
        "message": RULES["country_change"]["message"]
        if triggered else "Country remains same as previous transaction."
    }
    anomaly_score += score

    # ------------------------------------------
    # RULE 5: VERY SHORT TRANSACTION GAP
    # ------------------------------------------
    triggered = duration is not None and duration < 15
    score = RULES["transaction_duration"]["weight"] if triggered else 0
    rule_results["transaction_duration"] = {
        "score": score,
        "message": RULES["transaction_duration"]["message"]
        if triggered else "Transaction timing normal."
    }
    anomaly_score += score

    # ------------------------------------------
    # RULE 6: MIDNIGHT TRANSACTION
    # ------------------------------------------
    hour = txn_time.hour if isinstance(txn_time, datetime) else -1
    triggered = 0 <= hour <= 4
    score = RULES["midnight_transaction"]["weight"] if triggered else 0
    rule_results["midnight_transaction"] = {
        "score": score,
        "message": RULES["midnight_transaction"]["message"]
        if triggered else "Transaction time is normal."
    }
    anomaly_score += score

    # ------------------------------------------
    # RULE 7: HIGH AMOUNT (FIXED ✅)
    # ------------------------------------------
    triggered = (
        amount >= 1_000_000 and
        (prev_amount == 0 or amount >= prev_amount * 5)
    )

    score = RULES["high_amount_transaction"]["weight"] if triggered else 0
    rule_results["high_amount_transaction"] = {
        "score": score,
        "message": RULES["high_amount_transaction"]["message"]
        if triggered else "Transaction amount within normal limits."
    }
    anomaly_score += score

    # ------------------------------------------
    # FINAL RESULT
    # ------------------------------------------
    final_message = (
        "Several risk indicators detected."
        if anomaly_score >= 40 else
        "Minor unusual behavior detected."
        if anomaly_score > 0 else
        "No anomalies detected."
    )

    return {
        "total_score": anomaly_score,
        "rule_results": rule_results,
        "message": final_message
    }
