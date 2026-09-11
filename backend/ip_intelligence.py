import ipaddress


PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def analyze_ip(ip):

    if not ip:
        return {
            "ip": None,
            "classification": "UNKNOWN",
            "score": 0,
            "indicators": []
        }

    indicators = []
    score = 0

    try:
        address = ipaddress.ip_address(ip)

        # Private/local IP
        if address.is_private:

            indicators.append(
                "Sender IP belongs to a private/local network"
            )

            classification = "PRIVATE / LOCAL"

        # Loopback
        elif address.is_loopback:

            score += 10

            indicators.append(
                "Loopback IP address detected"
            )

            classification = "SUSPICIOUS"

        # Reserved
        elif address.is_reserved:

            score += 10

            indicators.append(
                "Reserved IP address detected"
            )

            classification = "SUSPICIOUS"

        # Normal public IP
        else:

            classification = "PUBLIC IP"

    except ValueError:

        score = 30

        classification = "SUSPICIOUS"

        indicators.append(
            "Invalid IP address format"
        )

    return {
        "ip": ip,
        "classification": classification,
        "score": score,
        "indicators": indicators
    }