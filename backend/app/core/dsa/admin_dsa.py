# app/core/dsa/admin_dsa.py
"""
Admin-specific DSA operations for the LinkLock Admin Panel.

DSA Concepts Implemented:
- LRU Cache (SETEX with TTL) - Dashboard stats caching
- Priority Queue (ZSET) - Alert severity ranking
- Counter (ZADD with timestamps) - Real-time active users
- Sliding Window (LIST + TTL) - Rate limiting
- Hash Map (HSET/HGET) - Admin session tracking
"""

import json
import time
from datetime import datetime, timedelta
from typing import List, Tuple, Optional, Any, Dict
from app.db.redis_client import rc, safe_json_dumps, is_redis_available


def clean_data_for_redis(data: Any) -> Any:
    """Recursively clean data to make it JSON-serializable"""
    if isinstance(data, datetime):
        return data.isoformat()
    elif isinstance(data, dict):
        return {k: clean_data_for_redis(v) for k, v in data.items()}
    elif isinstance(data, (list, tuple)):
        return [clean_data_for_redis(item) for item in data]
    else:
        return data


# ========================================
# LRU CACHE FOR DASHBOARD STATS
# ========================================

def cache_dashboard_stats(key: str, data: dict, ttl: int = 300) -> bool:
    """
    Cache dashboard statistics with TTL (default 5 minutes).
    DSA: LRU Cache using SETEX
    Time Complexity: O(1)
    """
    if not is_redis_available():
        return False

    try:
        cache_key = f"admin:cache:{key}"
        clean_data = clean_data_for_redis(data)
        rc.setex(cache_key, ttl, safe_json_dumps(clean_data))
        return True
    except Exception as e:
        print(f"❌ Error caching stats {key}: {e}")
        return False


def get_cached_stats(key: str) -> Optional[dict]:
    """
    Retrieve cached dashboard statistics.
    DSA: LRU Cache lookup
    Time Complexity: O(1)
    """
    if not is_redis_available():
        return None

    try:
        cache_key = f"admin:cache:{key}"
        cached = rc.get(cache_key)
        if cached:
            return json.loads(cached)
        return None
    except Exception as e:
        print(f"❌ Error getting cached stats {key}: {e}")
        return None


def invalidate_cache(key: str) -> bool:
    """Invalidate a specific cache key"""
    if not is_redis_available():
        return False

    try:
        cache_key = f"admin:cache:{key}"
        rc.delete(cache_key)
        return True
    except Exception as e:
        print(f"❌ Error invalidating cache {key}: {e}")
        return False


def invalidate_all_admin_cache() -> bool:
    """Invalidate all admin cache keys"""
    if not is_redis_available():
        return False

    try:
        keys = rc.keys("admin:cache:*")
        if keys:
            rc.delete(*keys)
        return True
    except Exception as e:
        print(f"❌ Error invalidating all cache: {e}")
        return False


# ========================================
# PRIORITY QUEUE FOR ALERTS (ZSET)
# ========================================

def push_alert_priority(alert_id: str, severity_score: float, alert_data: dict = None) -> bool:
    """
    Add alert to priority queue with severity score.
    DSA: Priority Queue using Sorted Set (ZSET)
    Time Complexity: O(log N)

    Higher score = higher priority (critical alerts first)
    Severity mapping: critical=100, warning=60, info=30
    """
    if not is_redis_available():
        return False

    try:
        rc.zadd("admin:alerts:priority", {alert_id: severity_score})

        # Store alert data in hash for quick lookup
        if alert_data:
            clean_data = clean_data_for_redis(alert_data)
            rc.hset("admin:alerts:data", alert_id, safe_json_dumps(clean_data))
            rc.expire("admin:alerts:data", 86400)  # 24 hours TTL

        return True
    except Exception as e:
        print(f"❌ Error pushing alert priority {alert_id}: {e}")
        return False


def get_top_alerts(limit: int = 10) -> List[Tuple[str, float]]:
    """
    Get highest priority alerts (without removing).
    DSA: Priority Queue peek operation
    Time Complexity: O(log N + M) where M is limit
    """
    if not is_redis_available():
        return []

    try:
        # Get top N alerts by score (descending)
        return rc.zrevrange("admin:alerts:priority", 0, limit - 1, withscores=True)
    except Exception as e:
        print(f"❌ Error getting top alerts: {e}")
        return []


def pop_top_alerts(limit: int = 10) -> List[Tuple[str, float, Optional[dict]]]:
    """
    Pop highest priority alerts (removes from queue).
    DSA: Priority Queue extract-max operation
    Time Complexity: O(log N + M)
    """
    if not is_redis_available():
        return []

    try:
        items = rc.zrevrange("admin:alerts:priority", 0, limit - 1, withscores=True)
        results = []

        for alert_id, score in items:
            # Get associated data
            data_raw = rc.hget("admin:alerts:data", alert_id)
            data = json.loads(data_raw) if data_raw else None
            results.append((alert_id, float(score), data))

            # Remove from queue
            rc.zrem("admin:alerts:priority", alert_id)
            rc.hdel("admin:alerts:data", alert_id)

        return results
    except Exception as e:
        print(f"❌ Error popping top alerts: {e}")
        return []


def update_alert_priority(alert_id: str, new_score: float) -> bool:
    """
    Update alert priority (for escalation/de-escalation).
    DSA: Priority Queue update operation
    Time Complexity: O(log N)
    """
    if not is_redis_available():
        return False

    try:
        rc.zadd("admin:alerts:priority", {alert_id: new_score})
        return True
    except Exception as e:
        print(f"❌ Error updating alert priority {alert_id}: {e}")
        return False


def remove_alert_from_queue(alert_id: str) -> bool:
    """Remove alert from priority queue (when resolved)"""
    if not is_redis_available():
        return False

    try:
        rc.zrem("admin:alerts:priority", alert_id)
        rc.hdel("admin:alerts:data", alert_id)
        return True
    except Exception as e:
        print(f"❌ Error removing alert {alert_id}: {e}")
        return False


def get_alert_queue_size() -> int:
    """Get total number of alerts in priority queue"""
    if not is_redis_available():
        return 0

    try:
        return rc.zcard("admin:alerts:priority")
    except Exception as e:
        print(f"❌ Error getting queue size: {e}")
        return 0


# ========================================
# ACTIVE USERS COUNTER (SLIDING WINDOW)
# ========================================

def track_user_activity(user_id: str) -> bool:
    """
    Track user activity for real-time active users count.
    DSA: Sliding Window using Sorted Set with timestamps
    Time Complexity: O(log N)

    Users are considered active for 15 minutes after last activity.
    """
    if not is_redis_available():
        return False

    try:
        now = time.time()
        # Add/update user with current timestamp as score
        rc.zadd("admin:active_users", {user_id: now})

        # Remove users inactive for more than 15 minutes (sliding window cleanup)
        cutoff = now - 900  # 15 minutes
        rc.zremrangebyscore("admin:active_users", 0, cutoff)

        return True
    except Exception as e:
        print(f"❌ Error tracking user activity {user_id}: {e}")
        return False


def get_active_user_count() -> int:
    """
    Get count of currently active users.
    DSA: Counter operation on sliding window
    Time Complexity: O(1)
    """
    if not is_redis_available():
        return 0

    try:
        # First cleanup stale entries
        cutoff = time.time() - 900
        rc.zremrangebyscore("admin:active_users", 0, cutoff)

        return rc.zcard("admin:active_users")
    except Exception as e:
        print(f"❌ Error getting active user count: {e}")
        return 0


def get_active_users(limit: int = 10) -> List[Tuple[str, float]]:
    """
    Get list of active users with their last activity time.
    DSA: Range query on sorted set
    Time Complexity: O(log N + M)
    """
    if not is_redis_available():
        return []

    try:
        # Cleanup first
        cutoff = time.time() - 900
        rc.zremrangebyscore("admin:active_users", 0, cutoff)

        # Get most recently active users
        return rc.zrevrange("admin:active_users", 0, limit - 1, withscores=True)
    except Exception as e:
        print(f"❌ Error getting active users: {e}")
        return []


# ========================================
# RATE LIMITING (SLIDING WINDOW)
# ========================================

def check_rate_limit(identifier: str, max_requests: int = 100, window_seconds: int = 60) -> Tuple[bool, int]:
    """
    Check if request is within rate limit.
    DSA: Sliding Window Rate Limiter using List + TTL
    Time Complexity: O(N) where N is number of requests in window

    Returns: (is_allowed, remaining_requests)
    """
    if not is_redis_available():
        return True, max_requests  # Allow if Redis unavailable

    try:
        key = f"admin:ratelimit:{identifier}"
        now = time.time()
        window_start = now - window_seconds

        # Remove old entries outside the window
        rc.zremrangebyscore(key, 0, window_start)

        # Count current requests in window
        current_count = rc.zcard(key)

        if current_count >= max_requests:
            return False, 0

        # Add new request
        rc.zadd(key, {f"{now}": now})
        rc.expire(key, window_seconds)

        remaining = max_requests - current_count - 1
        return True, remaining

    except Exception as e:
        print(f"❌ Error checking rate limit: {e}")
        return True, max_requests


# ========================================
# ADMIN SESSION TRACKING (HASH MAP)
# ========================================

def set_admin_session(admin_id: str, session_data: dict, ttl: int = 3600) -> bool:
    """
    Store admin session data.
    DSA: Hash Map using HSET
    Time Complexity: O(N) where N is number of fields
    """
    if not is_redis_available():
        return False

    try:
        key = f"admin:session:{admin_id}"
        clean_data = clean_data_for_redis(session_data)
        rc.set(key, safe_json_dumps(clean_data))
        rc.expire(key, ttl)
        return True
    except Exception as e:
        print(f"❌ Error setting admin session {admin_id}: {e}")
        return False


def get_admin_session(admin_id: str) -> Optional[dict]:
    """
    Retrieve admin session data.
    DSA: Hash Map lookup
    Time Complexity: O(1)
    """
    if not is_redis_available():
        return None

    try:
        key = f"admin:session:{admin_id}"
        data = rc.get(key)
        if data:
            return json.loads(data)
        return None
    except Exception as e:
        print(f"❌ Error getting admin session {admin_id}: {e}")
        return None


def delete_admin_session(admin_id: str) -> bool:
    """Delete admin session (logout)"""
    if not is_redis_available():
        return False

    try:
        key = f"admin:session:{admin_id}"
        rc.delete(key)
        return True
    except Exception as e:
        print(f"❌ Error deleting admin session {admin_id}: {e}")
        return False


# ========================================
# STATISTICS COUNTERS
# ========================================

def increment_counter(counter_name: str, amount: int = 1) -> int:
    """
    Increment a counter (for tracking stats).
    DSA: Counter using INCRBY
    Time Complexity: O(1)
    """
    if not is_redis_available():
        return 0

    try:
        key = f"admin:counter:{counter_name}"
        return rc.incrby(key, amount)
    except Exception as e:
        print(f"❌ Error incrementing counter {counter_name}: {e}")
        return 0


def get_counter(counter_name: str) -> int:
    """Get counter value"""
    if not is_redis_available():
        return 0

    try:
        key = f"admin:counter:{counter_name}"
        val = rc.get(key)
        return int(val) if val else 0
    except Exception as e:
        print(f"❌ Error getting counter {counter_name}: {e}")
        return 0


def reset_counter(counter_name: str) -> bool:
    """Reset counter to zero"""
    if not is_redis_available():
        return False

    try:
        key = f"admin:counter:{counter_name}"
        rc.delete(key)
        return True
    except Exception as e:
        print(f"❌ Error resetting counter {counter_name}: {e}")
        return False


# ========================================
# ADMIN DSA STATS
# ========================================

def get_admin_dsa_stats() -> Dict[str, Any]:
    """Get statistics about admin DSA operations"""
    if not is_redis_available():
        return {"status": "unavailable"}

    try:
        return {
            "status": "connected",
            "cache_keys": len(rc.keys("admin:cache:*")),
            "alert_queue_size": get_alert_queue_size(),
            "active_users": get_active_user_count(),
            "active_sessions": len(rc.keys("admin:session:*")),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}
