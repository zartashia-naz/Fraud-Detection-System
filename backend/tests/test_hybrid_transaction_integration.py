"""
Integration tests for hybrid transaction model
"""
import sys
import os
from datetime import datetime, timedelta

# Ensure backend package root is on sys.path (same as hybrid login tests)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.hybrid_model.hybrid_transaction import hybrid_transaction_decision


def verify_result_fields(res: dict) -> None:
    required = [
        "event_type", "rule_flag", "rule_score", "ml_score", "ml_iso_score", "ml_ae_score",
        "hybrid_score", "is_moderate", "is_anomaly"
    ]
    for r in required:
        assert r in res, f"Missing {r} in result"


def test_first_transaction():
    now = datetime(2024, 1, 1, 12, 0, 0)
    current = {
        "transaction_date": now,
        "amount": 10.0,
        "device_id": "dev-a",
        "ip": "10.0.0.1",
        "location": {"country": "US", "city": "NYC"},
    }

    res = hybrid_transaction_decision(current, None)
    verify_result_fields(res)

    # First txn -> rule_score should be 0
    assert res["rule_score"] == 0.0
    # hybrid_score should be in [0,1]
    assert 0.0 <= res["hybrid_score"] <= 1.0


def test_normal_transaction():
    now = datetime(2024, 1, 2, 14, 0, 0)
    last = {
        "transaction_date": now - timedelta(hours=1),
        "device_id": "dev-a",
        "ip": "10.0.0.1",
        "location": {"country": "US", "city": "NYC"},
    }
    current = {
        "transaction_date": now,
        "amount": 25.0,
        "device_id": "dev-a",
        "ip": "10.0.0.1",
        "location": {"country": "US", "city": "NYC"},
    }

    res = hybrid_transaction_decision(current, last)
    verify_result_fields(res)

    # Expect low hybrid score for normal behavior
    assert res["hybrid_score"] < 0.35
    assert res["is_anomaly"] == 0


def test_suspicious_transaction():
    now = datetime(2024, 1, 3, 2, 30, 0)  # early morning (midnight rule)
    last = {
        "transaction_date": now - timedelta(days=1),
        "device_id": "dev-a",
        "ip": "10.0.0.1",
        "location": {"country": "US", "city": "NYC"},
    }
    current = {
        "transaction_date": now,
        "amount": 9999.0,
        "device_id": "dev-b",  # device changed
        "ip": "203.0.113.5",  # ip changed
        "location": {"country": "RU", "city": "Moscow"},  # country changed
    }

    res = hybrid_transaction_decision(current, last)
    verify_result_fields(res)

    # With multiple rule triggers, expect anomaly flag
    assert res["rule_flag"] == 1
    assert res["is_anomaly"] == 1 or res["hybrid_score"] >= 0.7
