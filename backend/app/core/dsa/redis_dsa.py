# app/core/dsa/redis_dsa.py
import json
import time
from datetime import datetime
from typing import List, Tuple, Optional, Any, Dict
from app.db.redis_client import rc, safe_json_dumps, is_redis_available

"""
Redis DSA primitives used by routes/services:

- Recent queue (LIST) for last N transactions/logins
- Sliding window (LIST + TTL) for login attempts per minute
- Priority queue (ZSET) for anomaly scores
- Simple hash (HSET) to store last_device / last_ip
"""


def clean_data_for_redis(data: Any) -> Any:
    """
    Recursively clean data to make it JSON-serializable
    Handles datetime objects and nested structures
    """
    if isinstance(data, datetime):
        return data.isoformat()
    elif isinstance(data, dict):
        return {k: clean_data_for_redis(v) for k, v in data.items()}
    elif isinstance(data, (list, tuple)):
        return [clean_data_for_redis(item) for item in data]
    else:
        return data


# ========================================
# RECENT QUEUE (LIST)
# ========================================

def push_recent_txn(user_id: str, txn: dict, limit: int = 10) -> bool:
    """Push transaction to recent queue with error handling"""
    if not is_redis_available():
        print(f"⚠️ Redis unavailable - skipping push_recent_txn for user {user_id}")
        return False
    
    try:
        key = f"user:{user_id}:recent_txn"
        
        # Clean data before storing
        clean_txn = clean_data_for_redis(txn)
        
        rc.lpush(key, safe_json_dumps(clean_txn))
        rc.ltrim(key, 0, limit - 1)
        rc.expire(key, 60 * 60 * 24 * 7)  # keep 7 days
        
        print(f"✅ Pushed transaction to Redis for user {user_id}")
        return True
        
    except Exception as e:
        print(f"❌ Error in push_recent_txn for user {user_id}: {e}")
        return False


def get_recent_txns(user_id: str) -> List[dict]:
    """Get recent transactions with error handling"""
    if not is_redis_available():
        return []
    
    try:
        key = f"user:{user_id}:recent_txn"
        raw = rc.lrange(key, 0, -1)
        return [json.loads(r) for r in raw]
    except Exception as e:
        print(f"❌ Error in get_recent_txns for user {user_id}: {e}")
        return []


def push_recent_login(user_id: str, log: dict, limit: int = 10) -> bool:
    """Push login log to recent queue with error handling"""
    if not is_redis_available():
        print(f"⚠️ Redis unavailable - skipping push_recent_login for user {user_id}")
        return False
    
    try:
        key = f"user:{user_id}:recent_logins"
        
        # Clean data before storing
        clean_log = clean_data_for_redis(log)
        
        rc.lpush(key, safe_json_dumps(clean_log))
        rc.ltrim(key, 0, limit - 1)
        rc.expire(key, 60 * 60 * 24 * 7)
        
        print(f"✅ Pushed login to Redis for user {user_id}")
        return True
        
    except Exception as e:
        print(f"❌ Error in push_recent_login for user {user_id}: {e}")
        return False


def get_recent_logins(user_id: str) -> List[dict]:
    """Get recent logins with error handling"""
    if not is_redis_available():
        return []
    
    try:
        key = f"user:{user_id}:recent_logins"
        raw = rc.lrange(key, 0, -1)
        return [json.loads(r) for r in raw]
    except Exception as e:
        print(f"❌ Error in get_recent_logins for user {user_id}: {e}")
        return []


# ========================================
# SLIDING WINDOW FOR LOGIN ATTEMPTS
# ========================================

def record_login_attempt(user_id: str, ttl_seconds: int = 60) -> int:
    """Record login attempt with error handling"""
    if not is_redis_available():
        return 0
    
    try:
        key = f"user:{user_id}:attempts"
        now = time.time()
        rc.lpush(key, now)
        rc.expire(key, ttl_seconds)
        return rc.llen(key)
    except Exception as e:
        print(f"❌ Error in record_login_attempt for user {user_id}: {e}")
        return 0


def count_login_attempts(user_id: str) -> int:
    """Count login attempts with error handling"""
    if not is_redis_available():
        return 0
    
    try:
        key = f"user:{user_id}:attempts"
        return rc.llen(key)
    except Exception as e:
        print(f"❌ Error in count_login_attempts for user {user_id}: {e}")
        return 0


# ========================================
# PRIORITY QUEUE FOR ANOMALIES (ZSET)
# ========================================

def push_anomaly_score(anomaly_id: str, score: float, payload: dict, payload_ttl: int = 3600) -> bool:
    """Push anomaly score to priority queue with error handling"""
    if not is_redis_available():
        return False
    
    try:
        # Clean payload
        clean_payload = clean_data_for_redis(payload)
        
        rc.zadd("anomalies:queue", {anomaly_id: score})
        rc.hset("anomalies:payloads", anomaly_id, safe_json_dumps(clean_payload))
        rc.expire("anomalies:payloads", payload_ttl)
        
        print(f"✅ Pushed anomaly {anomaly_id} with score {score} to Redis")
        return True
        
    except Exception as e:
        print(f"❌ Error in push_anomaly_score for {anomaly_id}: {e}")
        return False


def peek_top_anomalies(limit: int = 10) -> List[Tuple[str, float]]:
    """Peek top anomalies without removing with error handling"""
    if not is_redis_available():
        return []
    
    try:
        return rc.zrevrange("anomalies:queue", 0, limit - 1, withscores=True)
    except Exception as e:
        print(f"❌ Error in peek_top_anomalies: {e}")
        return []


def pop_top_anomalies(limit: int = 10) -> List[Tuple[str, float, Optional[dict]]]:
    """Pop top anomalies with error handling"""
    if not is_redis_available():
        return []
    
    try:
        items = rc.zrevrange("anomalies:queue", 0, limit - 1, withscores=True)
        results = []
        
        for aid, score in items:
            payload_raw = rc.hget("anomalies:payloads", aid)
            payload = json.loads(payload_raw) if payload_raw else None
            results.append((aid, float(score), payload))
            
            # Remove from both structures
            rc.zrem("anomalies:queue", aid)
            rc.hdel("anomalies:payloads", aid)
        
        return results
        
    except Exception as e:
        print(f"❌ Error in pop_top_anomalies: {e}")
        return []


# ========================================
# LAST DEVICE/IP TRACKING
# ========================================

def set_last_device(user_id: str, device_id: str) -> bool:
    """Set last device with error handling"""
    if not is_redis_available():
        return False
    
    try:
        rc.hset("user:last_device", user_id, device_id)
        print(f"✅ Set last device for user {user_id}: {device_id}")
        return True
    except Exception as e:
        print(f"❌ Error in set_last_device for user {user_id}: {e}")
        return False


def get_last_device(user_id: str) -> Optional[str]:
    """Get last device with error handling"""
    if not is_redis_available():
        return None
    
    try:
        return rc.hget("user:last_device", user_id)
    except Exception as e:
        print(f"❌ Error in get_last_device for user {user_id}: {e}")
        return None


def set_last_ip(user_id: str, ip: str) -> bool:
    """Set last IP with error handling"""
    if not is_redis_available():
        return False
    
    try:
        rc.hset("user:last_ip", user_id, ip)
        print(f"✅ Set last IP for user {user_id}: {ip}")
        return True
    except Exception as e:
        print(f"❌ Error in set_last_ip for user {user_id}: {e}")
        return False


def get_last_ip(user_id: str) -> Optional[str]:
    """Get last IP with error handling"""
    if not is_redis_available():
        return None
    
    try:
        return rc.hget("user:last_ip", user_id)
    except Exception as e:
        print(f"❌ Error in get_last_ip for user {user_id}: {e}")
        return None


# ========================================
# UTILITY FUNCTIONS
# ========================================

def clear_user_data(user_id: str) -> bool:
    """Clear all Redis data for a user"""
    if not is_redis_available():
        return False
    
    try:
        keys_to_delete = [
            f"user:{user_id}:recent_txn",
            f"user:{user_id}:recent_logins",
            f"user:{user_id}:attempts",
        ]
        
        for key in keys_to_delete:
            rc.delete(key)
        
        rc.hdel("user:last_device", user_id)
        rc.hdel("user:last_ip", user_id)
        
        print(f"✅ Cleared all Redis data for user {user_id}")
        return True
        
    except Exception as e:
        print(f"❌ Error in clear_user_data for user {user_id}: {e}")
        return False


def get_redis_stats() -> Dict[str, Any]:
    """Get Redis statistics"""
    if not is_redis_available():
        return {"status": "unavailable"}
    
    try:
        info = rc.info()
        return {
            "status": "connected",
            "version": info.get("redis_version"),
            "connected_clients": info.get("connected_clients"),
            "used_memory_human": info.get("used_memory_human"),
            "total_keys": rc.dbsize(),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}