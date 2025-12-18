import requests

def get_location_from_ip(ip):
    try:
        url = f"https://ipapi.co/{ip}/json/"
        res = requests.get(url).json()

        return {
            "country": res.get("country_name"),
            "city": res.get("city"),
            "latitude": res.get("latitude"),
            "longitude": res.get("longitude")
        }
    except Exception as e:
        return {"error": str(e)}
