from datetime import datetime
from typing import Dict, Optional

# ----------------------------------------------------
# RULE-BASED ENGINE FOR TRANSACTION ANOMALY SCORE
# ----------------------------------------------------

def compute_rule_based_score(
    current_txn: Dict,
    last_txn: Optional[Dict] = None,
    user_stats: Optional[Dict] = None
) -> Dict:
    """
    Calculates rule-based anomaly score using deterministic rules.

    Args:
        current_txn: Current transaction data
        last_txn: Previous transaction (if exists)
        user_stats: User's historical statistics (optional but recommended)

    Returns:
        Dictionary with scores, triggered rules, messages, and action
    """

    # ------------------------------------------
    # RULE DEFINITIONS (UPDATED WEIGHTS, ADDED STRICT AMOUNT RULES)
    # ------------------------------------------
    RULES = {
        "device_change": {
            "weight": 15,
            "message": "Transaction made from a new or unusual device."
        },
        "ip_change": {
            "weight": 20,
            "message": "IP address changed from last known IP."
        },
        "city_change": {
            "weight": 25,
            "message": "Transaction performed from a new city."
        },
        "country_change": {
            "weight": 50,
            "message": "Transaction originated from a different country."
        },
        "transaction_duration": {
            "weight": 20,
            "message": "Two transactions made too quickly, suspicious rapid activity."
        },
        "midnight_transaction": {
            "weight": 10,
            "message": "Transaction made at unusual time (00:00–04:00)."
        },
        "high_risk_category": {
            "weight": 15,
            "message": "Transaction in high-risk category (Gambling, Crypto, etc.)."
        },
        "amount_moderate_risk": {
            "weight": 20,
            "message": "Moderate risk: Transaction amount is somewhat higher than usual."
        },
        "new_user_amount_moderate_risk": {
            "weight": 15,
            "message": "Moderate risk: First transaction with somewhat high amount."
        },
        "new_user_amount_anomaly": {
            "weight": 35,
            "message": "Anomaly: First transaction with very high amount."
        },
        "high_velocity": {
            "weight": 15,
            "message": "High transaction frequency in last hour."
        },
        "amount_anomaly": {
            "weight": 65,
            "message": "Significantly high amount."
        },  # Increased to trigger high
        "extreme_amount": {
            "weight": 30, 
            "message": "Extremely unusual amount (potential error or fraud)."
        },  # New
        # New Strict Amount Rules
        "strict_amount_low": {
            "weight": 0,
            "message": "Strict rule: Amount < $300,000 - Low risk."
        },
        "strict_amount_moderate": {
            "weight": 30,
            "message": "Strict rule: Amount $300,000 - $1,000,000 - Moderate risk."
        },
        "strict_amount_high": {
            "weight": 60,
            "message": "Strict rule: Amount > $1,000,000 - High risk."
        }
    }

    rule_results = {}
    anomaly_score = 0

    # ------------------------------------------
    # EXTRACT FIELDS SAFELY
    # ------------------------------------------
    amount = float(current_txn.get("amount", 0))

    new_device = current_txn.get("device_id")
    old_device = last_txn.get("device_id") if last_txn else None

    new_ip = current_txn.get("ip")
    old_ip = last_txn.get("ip") if last_txn else None

    new_loc = current_txn.get("location") or {}
    old_loc = (last_txn.get("location") or {}) if last_txn else {}

    txn_time = current_txn.get("transaction_date")
    duration = current_txn.get("transaction_duration")

    category = current_txn.get("category", "")

    # User statistics for better thresholds
    if user_stats:
        avg_amount = user_stats.get("avg_amount", 100.0)
        max_amount = user_stats.get("max_amount", 1000.0)
        transaction_count = user_stats.get("transaction_count", 0)
    else:
        avg_amount = 100.0
        max_amount = 1000.0
        transaction_count = 0 if last_txn is None else 1

    # ------------------------------------------
    # SPECIAL CASE: FIRST TRANSACTION
    # ------------------------------------------
    is_first_transaction = (last_txn is None) or (transaction_count == 0)

    if is_first_transaction:
        # Apply limited rules for first transaction

        # Rule: New user amount risk level
        triggered_moderate = 100 < amount <= 500
        triggered_anomaly = amount > 500
        if triggered_anomaly:
            key = "new_user_amount_anomaly"
            score = RULES[key]["weight"]
            message = RULES[key]["message"]
        elif triggered_moderate:
            key = "new_user_amount_moderate_risk"
            score = RULES[key]["weight"]
            message = RULES[key]["message"]
        else:
            key = "new_user_amount_low_risk"
            score = 0
            message = "Low risk: First transaction with normal amount."
        rule_results[key] = {
            "score": score,
            "message": message
        }
        anomaly_score += score

        # Rule: High-risk category for first transaction
        HIGH_RISK_CATEGORIES = ["Gambling", "Cryptocurrency", "International", "Cash Withdrawal"]
        if category in HIGH_RISK_CATEGORIES:
            score = RULES["high_risk_category"]["weight"]
            rule_results["high_risk_category"] = {
                "score": score,
                "message": RULES["high_risk_category"]["message"]
            }
            anomaly_score += score
        else:
            rule_results["high_risk_category"] = {
                "score": 0,
                "message": "Transaction category is low risk."
            }

        # Rule: Midnight transaction
        hour = txn_time.hour if isinstance(txn_time, datetime) else -1
        triggered = 0 <= hour <= 4
        score = RULES["midnight_transaction"]["weight"] if triggered else 0
        rule_results["midnight_transaction"] = {
            "score": score,
            "message": RULES["midnight_transaction"]["message"] if triggered else "Transaction time is normal."
        }
        anomaly_score += score

        # Rule: High velocity (though unlikely for first, but if tx_last_1hr >3 somehow)
        tx_last_1hr = current_txn.get("tx_last_1hr", 0)
        triggered = tx_last_1hr > 3
        score = RULES["high_velocity"]["weight"] if triggered else 0
        rule_results["high_velocity"] = {
            "score": score,
            "message": RULES["high_velocity"]["message"] if triggered else "Normal frequency."
        }
        anomaly_score += score

    else:
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
        # RULE 7: AMOUNT RISK LEVEL (TIERED)
        # ------------------------------------------
        absolute_threshold = 10000.0
        triggered_moderate = avg_amount * 2 < amount <= avg_amount * 5
        triggered_anomaly = amount > avg_amount * 5 or amount > max_amount * 2.0 or amount > absolute_threshold
        if triggered_anomaly:
            key = "amount_anomaly"
            score = RULES["amount_anomaly"]["weight"]
            message = RULES["amount_anomaly"]["message"]
        elif triggered_moderate:
            key = "amount_moderate_risk"
            score = RULES["amount_moderate_risk"]["weight"]
            message = RULES["amount_moderate_risk"]["message"]
        else:
            key = "amount_low_risk"
            score = 0
            message = "Low risk: Transaction amount is within normal range."
        rule_results[key] = {
            "score": score,
            "message": message
        }
        anomaly_score += score

        triggered_extreme = amount > 1e6
        score = RULES["extreme_amount"]["weight"] if triggered_extreme else 0
        rule_results["extreme_amount"] = {
            "score": score,
            "message": RULES["extreme_amount"]["message"] if triggered_extreme else "Amount not extreme."
        }
        anomaly_score += score

        # ------------------------------------------
        # RULE 8: HIGH-RISK CATEGORY
        # ------------------------------------------
        HIGH_RISK_CATEGORIES = ["Gambling", "Cryptocurrency", "International", "Cash Withdrawal"]
        triggered = category in HIGH_RISK_CATEGORIES
        score = RULES["high_risk_category"]["weight"] if triggered else 0
        rule_results["high_risk_category"] = {
            "score": score,
            "message": RULES["high_risk_category"]["message"]
            if triggered else "Transaction category is low risk."
        }
        anomaly_score += score

        # ------------------------------------------
        # RULE 9: HIGH VELOCITY
        # ------------------------------------------
        tx_last_1hr = current_txn.get("tx_last_1hr", 0)
        triggered = tx_last_1hr > 3
        score = RULES["high_velocity"]["weight"] if triggered else 0
        rule_results["high_velocity"] = {
            "score": score,
            "message": RULES["high_velocity"]["message"] if triggered else "Normal frequency."
        }
        anomaly_score += score

    # ------------------------------------------
    # ADD STRICT AMOUNT RULES (ALWAYS EXECUTED)
    # ------------------------------------------
    if amount < 300000:
        key = "strict_amount_low"
        score = RULES[key]["weight"]
        message = RULES[key]["message"]
    elif 300000 <= amount <= 1000000:
        key = "strict_amount_moderate"
        score = RULES[key]["weight"]
        message = RULES[key]["message"]
    else:
        key = "strict_amount_high"
        score = RULES[key]["weight"]
        message = RULES[key]["message"]
    rule_results[key] = {
        "score": score,
        "message": message
    }
    anomaly_score += score

    # ------------------------------------------
    # COMPUTE BASE MESSAGE BASED ON SCORE
    # ------------------------------------------
    base_message = (
        "High risk - multiple indicators detected."
        if anomaly_score >= 60 else
        "Moderate risk - some unusual behavior."
        if anomaly_score >= 30 else
        "Low risk - normal transaction."
    )
    base_action = (
        "Block account" if anomaly_score >= 60 else
        "Trigger OTP" if anomaly_score >= 30 else
        "Transaction successful"
    )

    # ------------------------------------------
    # OVERRIDE FINAL MESSAGE/ACTION BASED ON STRICT AMOUNT (TO ENFORCE REQUIREMENTS)
    # ------------------------------------------
    if amount < 300000:
        final_message = "Low risk - normal transaction."
        final_action = "Transaction successful"
    elif amount > 1000000:
        final_message = "High risk - multiple indicators detected."
        final_action = "Block account"
    else:  # 300000 <= amount <= 1000000
        # Use base, but ensure at least moderate
        final_message = base_message if anomaly_score >= 30 else "Moderate risk - some unusual behavior."
        final_action = base_action if anomaly_score >= 30 else "Trigger OTP"

    return {
        "total_score": anomaly_score,
        "rule_results": rule_results,
        "is_first_transaction": is_first_transaction,
        "message": final_message,
        "action": final_action
    }