# app/db/redis_client.py
import os
import redis
import json
from datetime import datetime
from typing import Any, Optional

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Initialize Redis connection with error handling
try:
    rc = redis.from_url(REDIS_URL, decode_responses=True)
    # Test connection
    rc.ping()
    print("✅ Redis connected successfully")
except redis.ConnectionError as e:
    print(f"⚠️ Redis connection failed: {e}")
    print("⚠️ Redis features will be disabled")
    rc = None
except Exception as e:
    print(f"⚠️ Unexpected Redis error: {e}")
    rc = None


def datetime_serializer(obj):
    """Convert datetime objects to ISO format strings"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def safe_json_dumps(data: Any) -> str:
    """Safely serialize data to JSON, handling datetime objects"""
    return json.dumps(data, default=datetime_serializer)


def r_get(key: str) -> Optional[Any]:
    """Get value from Redis with error handling"""
    if not rc:
        return None
    
    try:
        v = rc.get(key)
        return json.loads(v) if v else None
    except redis.RedisError as e:
        print(f"Redis GET error for key '{key}': {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"JSON decode error for key '{key}': {e}")
        return None


def r_set(key: str, value: Any, ex: Optional[int] = None) -> bool:
    """Set value in Redis with error handling"""
    if not rc:
        return False
    
    try:
        rc.set(key, safe_json_dumps(value), ex=ex)
        return True
    except redis.RedisError as e:
        print(f"Redis SET error for key '{key}': {e}")
        return False
    except (TypeError, ValueError) as e:
        print(f"Serialization error for key '{key}': {e}")
        return False


def is_redis_available() -> bool:
    """Check if Redis is available"""
    if not rc:
        return False
    
    try:
        rc.ping()
        return True
    except:
        return False