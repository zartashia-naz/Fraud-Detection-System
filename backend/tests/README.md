# Hybrid Login Detection Integration Tests

This directory contains comprehensive tests for the hybrid login detection integration.

## Test Coverage

The test suite covers all critical scenarios:

1. **First Login** - Tests behavior when no previous login exists
2. **Normal Login** - Tests normal login with no anomalies
3. **Suspicious Login** - Tests login with device/IP/location changes
4. **Failed Login** - Tests failed login attempt detection
5. **MongoDB Storage** - Verifies all detection fields are stored correctly
6. **API Response** - Verifies API response includes all detection fields

## Running Tests

### Option 1: Direct Python Execution

```bash
cd backend
python tests/test_hybrid_login_integration.py
```

### Option 2: Using pytest (if installed)

```bash
cd backend
pytest tests/test_hybrid_login_integration.py -v
```

### Option 3: Run specific test

```python
from tests.test_hybrid_login_integration import test_first_login
test_first_login()
```

## Test Output

Tests provide colored output:
- ✓ Green: Test passed
- ✗ Red: Test failed
- ℹ Yellow: Information

## What Each Test Verifies

### Test 1: First Login
- Feature extraction handles missing previous login
- Default values are set correctly (device_changed=0, etc.)
- Detection runs without errors
- Model fields are populated

### Test 2: Normal Login
- Normal login features are extracted correctly
- No anomalies detected for normal behavior
- Hybrid score is low (< 0.35)

### Test 3: Suspicious Login
- Change detection works (device, IP, location)
- Suspicious patterns trigger higher scores
- Anomaly or moderate flag is set

### Test 4: Failed Login
- Failed login status is detected
- Failed login increases suspicion score

### Test 5: MongoDB Storage
- All detection fields serialize correctly
- Model can be converted to dict for MongoDB
- None values are handled properly

### Test 6: API Response
- Response schema includes all detection fields
- Fields can be serialized to JSON
- Field values are correct

## Expected Results

All tests should pass. If any test fails:
1. Check the error message
2. Verify the hybrid model files exist (`login_isolation_forest.pkl`, `login_event_scaler.pkl`)
3. Ensure all dependencies are installed
4. Check that feature extraction logic matches expected behavior

## Dependencies

Tests require:
- pandas
- numpy
- app modules (hybrid_login, login_feature_extractor, etc.)

Install with:
```bash
pip install -r requirements.txt
```
