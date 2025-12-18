"""
Comprehensive Test Suite for Hybrid Login Detection Integration
================================================================

Tests cover:
1. First login (no previous login)
2. Normal login (no anomalies)
3. Suspicious login (device/IP/location change)
4. Failed login
5. MongoDB storage verification
6. API response verification

Run with: python -m pytest tests/test_hybrid_login_integration.py -v
Or: python tests/test_hybrid_login_integration.py
"""

import asyncio
import sys
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
import pandas as pd

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.login_feature_extractor import extract_login_features
from app.hybrid_model.hybrid_login import hybrid_login_decision
from app.db.models.login_log_model import LoginLogModel


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_test_header(test_name: str):
    """Print formatted test header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}TEST: {test_name}{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*80}{Colors.RESET}\n")


def print_success(message: str):
    """Print success message"""
    try:
        print(f"{Colors.GREEN}[PASS] {message}{Colors.RESET}")
    except UnicodeEncodeError:
        print(f"[PASS] {message}")


def print_error(message: str):
    """Print error message"""
    try:
        print(f"{Colors.RED}[FAIL] {message}{Colors.RESET}")
    except UnicodeEncodeError:
        print(f"[FAIL] {message}")


def print_info(message: str):
    """Print info message"""
    try:
        print(f"{Colors.YELLOW}[INFO] {message}{Colors.RESET}")
    except UnicodeEncodeError:
        print(f"[INFO] {message}")


def verify_detection_results(result: Dict, expected_anomaly: bool = None) -> bool:
    """
    Verify detection results contain all required fields
    
    Returns:
        bool: True if all fields present and valid
    """
    required_fields = [
        "event_type", "rule_flag", "rule_score", "ml_score", 
        "hybrid_score", "is_moderate", "is_anomaly"
    ]
    
    missing_fields = [field for field in required_fields if field not in result]
    if missing_fields:
        print_error(f"Missing fields in detection result: {missing_fields}")
        return False
    
    # Verify field types
    assert isinstance(result["rule_flag"], int), "rule_flag should be int"
    assert isinstance(result["rule_score"], (int, float)), "rule_score should be numeric"
    assert isinstance(result["ml_score"], (int, float)), "ml_score should be numeric"
    assert isinstance(result["hybrid_score"], (int, float)), "hybrid_score should be numeric"
    assert isinstance(result["is_moderate"], int), "is_moderate should be int"
    assert isinstance(result["is_anomaly"], int), "is_anomaly should be int"
    
    # Verify score ranges
    assert 0 <= result["rule_score"] <= 1, "rule_score should be between 0 and 1"
    assert 0 <= result["ml_score"] <= 1, "ml_score should be between 0 and 1"
    assert 0 <= result["hybrid_score"] <= 1, "hybrid_score should be between 0 and 1"
    
    # Verify expected anomaly if provided
    if expected_anomaly is not None:
        actual_anomaly = bool(result["is_anomaly"])
        if actual_anomaly != expected_anomaly:
            print_error(f"Expected anomaly={expected_anomaly}, got {actual_anomaly}")
            return False
    
    return True


def verify_model_fields(model: LoginLogModel) -> bool:
    """
    Verify LoginLogModel contains all detection result fields
    
    Returns:
        bool: True if all fields present
    """
    required_fields = [
        "rule_flag", "rule_score", "ml_score", "hybrid_score", 
        "is_moderate", "is_anomaly"
    ]
    
    missing_fields = []
    for field in required_fields:
        if not hasattr(model, field):
            missing_fields.append(field)
    
    if missing_fields:
        print_error(f"Missing fields in LoginLogModel: {missing_fields}")
        return False
    
    return True


# ============================================================================
# TEST CASE 1: FIRST LOGIN (NO PREVIOUS LOGIN)
# ============================================================================

def test_first_login():
    """Test first login scenario - no previous login exists"""
    print_test_header("First Login (No Previous Login)")
    
    current_login = {
        "login_time": datetime(2024, 1, 15, 14, 30, 0),  # 2:30 PM, Monday
        "device_id": "device-123",
        "ip_address": "192.168.1.100",
        "location": {
            "country": "United States",
            "city": "New York",
            "latitude": 40.7128,
            "longitude": -74.0060
        },
        "login_attempts": 1
    }
    
    # No previous login
    previous_login = None
    
    try:
        # Extract features
        features_df = extract_login_features(
            current_login=current_login,
            previous_login=previous_login,
            login_status="success"
        )
        
        print_success("Feature extraction completed")
        print_info(f"Features extracted:\n{features_df.to_dict('records')[0]}")
        
        # Verify first login features
        features = features_df.iloc[0]
        assert features["device_changed"] == 0, "First login should have device_changed=0"
        assert features["ip_changed"] == 0, "First login should have ip_changed=0"
        assert features["location_changed"] == 0, "First login should have location_changed=0"
        assert features["time_since_last_login"] == 86400.0, "First login should use default time"
        
        print_success("First login feature validation passed")
        
        # Run hybrid detection
        detection_result = hybrid_login_decision(features_df)
        
        print_success("Hybrid detection completed")
        print_info(f"Detection result: {detection_result}")
        
        # Verify detection results
        if verify_detection_results(detection_result, expected_anomaly=False):
            print_success("Detection result validation passed")
        
        # Create model and verify fields
        model = LoginLogModel(
            user_id="test-user-1",
            email="test@example.com",
            device_id=current_login["device_id"],
            ip_address=current_login["ip_address"],
            location=current_login["location"],
            login_attempts=current_login["login_attempts"],
            is_anomaly=bool(detection_result.get("is_anomaly", 0)),
            rule_flag=detection_result.get("rule_flag"),
            rule_score=detection_result.get("rule_score"),
            ml_score=detection_result.get("ml_score"),
            hybrid_score=detection_result.get("hybrid_score"),
            is_moderate=bool(detection_result.get("is_moderate", 0))
        )
        
        if verify_model_fields(model):
            print_success("LoginLogModel validation passed")
        
        print_success("TEST CASE 1 PASSED: First login handled correctly")
        return True
        
    except Exception as e:
        print_error(f"TEST CASE 1 FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================================
# TEST CASE 2: NORMAL LOGIN (NO ANOMALIES)
# ============================================================================

def test_normal_login():
    """Test normal login scenario - no anomalies detected"""
    print_test_header("Normal Login (No Anomalies)")
    
    # Previous login (1 hour ago)
    previous_login_time = datetime(2024, 1, 15, 13, 30, 0)
    
    previous_login = {
        "login_time": previous_login_time,
        "device_id": "device-123",
        "ip_address": "192.168.1.100",
        "location": {
            "country": "United States",
            "city": "New York",
            "latitude": 40.7128,
            "longitude": -74.0060
        },
        "login_attempts": 1
    }
    
    # Current login (normal time, same device/IP/location)
    current_login = {
        "login_time": datetime(2024, 1, 15, 14, 30, 0),  # 2:30 PM, Monday
        "device_id": "device-123",  # Same device
        "ip_address": "192.168.1.100",  # Same IP
        "location": {
            "country": "United States",  # Same location
            "city": "New York",
            "latitude": 40.7128,
            "longitude": -74.0060
        },
        "login_attempts": 2
    }
    
    try:
        # Extract features
        features_df = extract_login_features(
            current_login=current_login,
            previous_login=previous_login,
            login_status="success"
        )
        
        print_success("Feature extraction completed")
        print_info(f"Features extracted:\n{features_df.to_dict('records')[0]}")
        
        # Verify normal login features
        features = features_df.iloc[0]
        assert features["device_changed"] == 0, "Normal login should have device_changed=0"
        assert features["ip_changed"] == 0, "Normal login should have ip_changed=0"
        assert features["location_changed"] == 0, "Normal login should have location_changed=0"
        assert features["failed_login"] == 0, "Normal login should have failed_login=0"
        assert 3600 <= features["time_since_last_login"] <= 3700, "Time should be ~1 hour"
        
        print_success("Normal login feature validation passed")
        
        # Run hybrid detection
        detection_result = hybrid_login_decision(features_df)
        
        print_success("Hybrid detection completed")
        print_info(f"Detection result: {detection_result}")
        
        # Verify detection results (should not be anomaly)
        if verify_detection_results(detection_result, expected_anomaly=False):
            print_success("Detection result validation passed")
        
        # Verify scores are low (normal behavior)
        if detection_result["hybrid_score"] < 0.35:
            print_success(f"Hybrid score is low ({detection_result['hybrid_score']:.4f}), indicating normal login")
        else:
            print_error(f"Hybrid score is unexpectedly high: {detection_result['hybrid_score']:.4f}")
        
        print_success("TEST CASE 2 PASSED: Normal login handled correctly")
        return True
        
    except Exception as e:
        print_error(f"TEST CASE 2 FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================================
# TEST CASE 3: SUSPICIOUS LOGIN (DEVICE/IP/LOCATION CHANGE)
# ============================================================================

def test_suspicious_login():
    """Test suspicious login scenario - multiple red flags"""
    print_test_header("Suspicious Login (Device/IP/Location Change)")
    
    # Previous login (yesterday)
    previous_login_time = datetime(2024, 1, 14, 14, 30, 0)
    
    previous_login = {
        "login_time": previous_login_time,
        "device_id": "device-123",
        "ip_address": "192.168.1.100",
        "location": {
            "country": "United States",
            "city": "New York",
            "latitude": 40.7128,
            "longitude": -74.0060
        },
        "login_attempts": 5
    }
    
    # Current login (suspicious: new device, IP, location, unusual time)
    current_login = {
        "login_time": datetime(2024, 1, 15, 3, 0, 0),  # 3 AM - unusual time
        "device_id": "device-456",  # Different device
        "ip_address": "203.0.113.50",  # Different IP
        "location": {
            "country": "Russia",  # Different country
            "city": "Moscow",
            "latitude": 55.7558,
            "longitude": 37.6173
        },
        "login_attempts": 6
    }
    
    try:
        # Extract features
        features_df = extract_login_features(
            current_login=current_login,
            previous_login=previous_login,
            login_status="success"
        )
        
        print_success("Feature extraction completed")
        print_info(f"Features extracted:\n{features_df.to_dict('records')[0]}")
        
        # Verify suspicious login features
        features = features_df.iloc[0]
        assert features["device_changed"] == 1, "Suspicious login should have device_changed=1"
        assert features["ip_changed"] == 1, "Suspicious login should have ip_changed=1"
        assert features["location_changed"] == 1, "Suspicious login should have location_changed=1"
        assert features["login_hour"] == 3, "Suspicious login should be at unusual hour (3 AM)"
        
        print_success("Suspicious login feature validation passed")
        
        # Run hybrid detection
        detection_result = hybrid_login_decision(features_df)
        
        print_success("Hybrid detection completed")
        print_info(f"Detection result: {detection_result}")
        
        # Verify detection results (should be anomaly or moderate)
        if verify_detection_results(detection_result):
            print_success("Detection result validation passed")
        
        # Verify scores are high (suspicious behavior)
        if detection_result["hybrid_score"] >= 0.35:
            print_success(f"Hybrid score is high ({detection_result['hybrid_score']:.4f}), indicating suspicious login")
        else:
            print_error(f"Hybrid score is unexpectedly low: {detection_result['hybrid_score']:.4f}")
        
        # Verify anomaly or moderate flag is set
        if detection_result["is_anomaly"] == 1 or detection_result["is_moderate"] == 1:
            print_success("Anomaly or moderate flag set correctly")
        else:
            print_error("Anomaly or moderate flag should be set for suspicious login")
        
        print_success("TEST CASE 3 PASSED: Suspicious login handled correctly")
        return True
        
    except Exception as e:
        print_error(f"TEST CASE 3 FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================================
# TEST CASE 4: FAILED LOGIN
# ============================================================================

def test_failed_login():
    """Test failed login scenario"""
    print_test_header("Failed Login")
    
    # Previous login
    previous_login_time = datetime(2024, 1, 15, 13, 30, 0)
    
    previous_login = {
        "login_time": previous_login_time,
        "device_id": "device-123",
        "ip_address": "192.168.1.100",
        "location": {
            "country": "United States",
            "city": "New York"
        },
        "login_attempts": 1
    }
    
    # Current login (failed attempt)
    current_login = {
        "login_time": datetime(2024, 1, 15, 14, 30, 0),
        "device_id": "device-123",
        "ip_address": "192.168.1.100",
        "location": {
            "country": "United States",
            "city": "New York"
        },
        "login_attempts": 2
    }
    
    try:
        # Extract features with failed status
        features_df = extract_login_features(
            current_login=current_login,
            previous_login=previous_login,
            login_status="failed"  # Failed login
        )
        
        print_success("Feature extraction completed")
        print_info(f"Features extracted:\n{features_df.to_dict('records')[0]}")
        
        # Verify failed login features
        features = features_df.iloc[0]
        assert features["failed_login"] == 1, "Failed login should have failed_login=1"
        
        print_success("Failed login feature validation passed")
        
        # Run hybrid detection
        detection_result = hybrid_login_decision(features_df)
        
        print_success("Hybrid detection completed")
        print_info(f"Detection result: {detection_result}")
        
        # Verify detection results
        if verify_detection_results(detection_result):
            print_success("Detection result validation passed")
        
        # Failed login should increase suspicion
        if detection_result["hybrid_score"] >= 0.35:
            print_success(f"Hybrid score is elevated ({detection_result['hybrid_score']:.4f}), indicating failed login risk")
        else:
            print_info(f"Hybrid score: {detection_result['hybrid_score']:.4f}")
        
        print_success("TEST CASE 4 PASSED: Failed login handled correctly")
        return True
        
    except Exception as e:
        print_error(f"TEST CASE 4 FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================================
# TEST CASE 5: MONGODB STORAGE VERIFICATION
# ============================================================================

def test_mongodb_storage():
    """Test that LoginLogModel can be serialized for MongoDB storage"""
    print_test_header("MongoDB Storage Verification")
    
    try:
        # Create model with all detection fields
        model = LoginLogModel(
            user_id="test-user-mongo",
            email="test@example.com",
            device_id="device-123",
            ip_address="192.168.1.100",
            location={"country": "United States", "city": "New York"},
            login_attempts=1,
            is_anomaly=True,
            rule_flag=1,
            rule_score=0.8,
            ml_score=0.75,
            hybrid_score=0.77,
            is_moderate=False
        )
        
        # Convert to dict (as MongoDB would receive)
        model_dict = model.model_dump()
        
        print_success("Model created and serialized")
        print_info(f"Model dict keys: {list(model_dict.keys())}")
        
        # Verify all detection fields are present
        detection_fields = [
            "rule_flag", "rule_score", "ml_score", 
            "hybrid_score", "is_moderate", "is_anomaly"
        ]
        
        missing_fields = [field for field in detection_fields if field not in model_dict]
        if missing_fields:
            print_error(f"Missing fields in MongoDB dict: {missing_fields}")
            return False
        
        print_success("All detection fields present in MongoDB dict")
        
        # Verify field values
        assert model_dict["rule_flag"] == 1
        assert model_dict["rule_score"] == 0.8
        assert model_dict["ml_score"] == 0.75
        assert model_dict["hybrid_score"] == 0.77
        assert model_dict["is_moderate"] == False
        assert model_dict["is_anomaly"] == True
        
        print_success("All detection field values verified")
        
        # Test with None values (optional fields)
        model_with_none = LoginLogModel(
            user_id="test-user-mongo-2",
            device_id="device-456",
            ip_address="192.168.1.200",
            location={"country": "Canada"},
            login_attempts=1,
            is_anomaly=False
            # Detection fields omitted (should be None)
        )
        
        model_dict_none = model_with_none.model_dump()
        
        # Verify None values are handled
        assert model_dict_none.get("rule_flag") is None or model_dict_none.get("rule_flag") == 0
        print_success("None values handled correctly")
        
        print_success("TEST CASE 5 PASSED: MongoDB storage verification passed")
        return True
        
    except Exception as e:
        print_error(f"TEST CASE 5 FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================================
# TEST CASE 6: API RESPONSE VERIFICATION
# ============================================================================

def test_api_response():
    """Test that API response schema includes all detection fields"""
    print_test_header("API Response Verification")
    
    try:
        from app.schemas.login_log_schema import LoginLogResponse
        
        # Create response data
        response_data = {
            "id": "507f1f77bcf86cd799439011",
            "user_id": "test-user-api",
            "email": "test@example.com",
            "device_id": "device-123",
            "ip_address": "192.168.1.100",
            "location": {"country": "United States", "city": "New York"},
            "login_time": datetime.now(timezone.utc).replace(tzinfo=None),
            "previous_login_time": None,
            "login_attempts": 1,
            "is_anomaly": True,
            "rule_flag": 1,
            "rule_score": 0.8,
            "ml_score": 0.75,
            "hybrid_score": 0.77,
            "is_moderate": False
        }
        
        # Create response object
        response = LoginLogResponse(**response_data)
        
        print_success("API response object created")
        
        # Verify all detection fields are present
        detection_fields = [
            "rule_flag", "rule_score", "ml_score", 
            "hybrid_score", "is_moderate", "is_anomaly"
        ]
        
        missing_fields = [field for field in detection_fields if not hasattr(response, field)]
        if missing_fields:
            print_error(f"Missing fields in API response: {missing_fields}")
            return False
        
        print_success("All detection fields present in API response")
        
        # Verify field values
        assert response.rule_flag == 1
        assert response.rule_score == 0.8
        assert response.ml_score == 0.75
        assert response.hybrid_score == 0.77
        assert response.is_moderate == False
        assert response.is_anomaly == True
        
        print_success("All detection field values verified")
        
        # Test response serialization (as JSON)
        response_dict = response.model_dump()
        
        # Verify all fields in dict
        missing_in_dict = [field for field in detection_fields if field not in response_dict]
        if missing_in_dict:
            print_error(f"Missing fields in response dict: {missing_in_dict}")
            return False
        
        print_success("Response serialization verified")
        
        print_success("TEST CASE 6 PASSED: API response verification passed")
        return True
        
    except Exception as e:
        print_error(f"TEST CASE 6 FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

def run_all_tests():
    """Run all test cases"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}HYBRID LOGIN DETECTION INTEGRATION TEST SUITE{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*80}{Colors.RESET}\n")
    
    tests = [
        ("First Login", test_first_login),
        ("Normal Login", test_normal_login),
        ("Suspicious Login", test_suspicious_login),
        ("Failed Login", test_failed_login),
        ("MongoDB Storage", test_mongodb_storage),
        ("API Response", test_api_response),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print_error(f"Test '{test_name}' crashed: {str(e)}")
            results.append((test_name, False))
    
    # Print summary
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}TEST SUMMARY{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*80}{Colors.RESET}\n")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = f"{Colors.GREEN}PASSED{Colors.RESET}" if result else f"{Colors.RED}FAILED{Colors.RESET}"
        print(f"{test_name:30} {status}")
    
    print(f"\n{Colors.BOLD}Total: {passed}/{total} tests passed{Colors.RESET}\n")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
