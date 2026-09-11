import ipaddress
import requests


def is_private_ip(ip):
    try:
        address = ipaddress.ip_address(ip)
        return (
            address.is_private
            or address.is_loopback
            or address.is_reserved
            or address.is_link_local
        )
    except ValueError:
        return False


def geolocate_ip(ip):

    result = {
        "ip": ip,
        "status": "UNKNOWN",
        "country": None,
        "region": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "isp": None,
        "organization": None,
        "timezone": None,
        "indicators": []
    }

    if not ip:
        result["status"] = "NO IP"
        result["indicators"].append("No sender IP available")
        return result

    if is_private_ip(ip):
        result["status"] = "PRIVATE IP"
        result["indicators"].append(
            "Private/local IP cannot be geolocated on the public Internet"
        )
        return result

    try:
        url = f"http://ip-api.com/json/{ip}"

        response = requests.get(
            url,
            params={
                "fields": (
                    "status,message,country,regionName,city,"
                    "lat,lon,isp,org,timezone,query"
                )
            },
            timeout=5
        )

        data = response.json()

        if data.get("status") != "success":
            result["status"] = "LOOKUP FAILED"
            result["indicators"].append(
                data.get("message", "IP geolocation lookup failed")
            )
            return result

        result.update({
            "status": "LOCATED",
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "isp": data.get("isp"),
            "organization": data.get("org"),
            "timezone": data.get("timezone")
        })

        return result

    except requests.RequestException as error:
        result["status"] = "NETWORK ERROR"
        result["indicators"].append(
            f"Geolocation service unavailable: {str(error)}"
        )
        return result

    except Exception as error:
        result["status"] = "ERROR"
        result["indicators"].append(
            f"Geolocation error: {str(error)}"
        )
        return result