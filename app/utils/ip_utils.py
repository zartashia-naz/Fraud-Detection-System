# from fastapi import Request

# def get_client_ip(request: Request) -> str:
#     """
#     Extract client IP address from the request.
#     Works even behind proxies.
#     """
#     x_forwarded_for = request.headers.get("X-Forwarded-For")
#     if x_forwarded_for:
#         # Sometimes the header contains multiple IPs -> take first
#         ip = x_forwarded_for.split(",")[0].strip()
#     else:
#         ip = request.client.host

#     return ip



# ===========claude code below==================

# backend/app/utils/ip_utils.py

from fastapi import Request
import requests
from typing import Optional, Dict, Any

def get_client_ip(request: Request) -> str:
    """
    Extract real client IP (handles proxies/load balancers)
    """
    # Check common proxy headers
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to direct client
    return request.client.host if request.client else "unknown"


async def get_geolocation(ip_address: str) -> Dict[str, Any]:
    """
    Get geolocation from IP address using free IP-API service
    """
    if ip_address in ["127.0.0.1", "localhost", "unknown"]:
        return {
            "country": "Pakistan",
            "city": "Lahore",
            "latitude": 31.5204,
            "longitude": 74.3587,
            "timezone": "Asia/Karachi",
            "isp": "Local",
        }
    
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_address}",
            timeout=3
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "region": data.get("regionName"),
                }
    except Exception as e:
        print(f"Geolocation error for {ip_address}: {e}")
    
    # Fallback
    return {
        "country": "Unknown",
        "city": "Unknown",
        "latitude": None,
        "longitude": None,
        "timezone": "Unknown",
        "isp": "Unknown",
    }


def check_vpn_tor(ip_address: str) -> Dict[str, bool]:
    """
    Check if IP is VPN/Tor (basic check)
    For production, use services like IPQualityScore or IPHub
    """
    # For now, basic checks
    if ip_address in ["127.0.0.1", "localhost"]:
        return {"is_vpn": False, "is_tor": False, "is_proxy": False}
    
    # TODO: Integrate with VPN detection API in production
    return {
        "is_vpn": False,
        "is_tor": False,
        "is_proxy": False,
        "risk_score": 0,
    }