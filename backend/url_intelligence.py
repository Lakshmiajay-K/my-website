import re
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".xyz", ".click", ".zip", ".mov"
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly"
}


def get_domain_from_email(sender):

    if not sender or "@" not in sender:
        return None

    return sender.split("@")[-1].lower().strip()


def analyze_url(url, sender_domain=None):

    indicators = []
    score = 0

    try:

        parsed = urlparse(url)

        hostname = (parsed.hostname or "").lower()

        if not hostname:

            return {
                "url": url,
                "domain": None,
                "score": 0,
                "classification": "UNKNOWN",
                "indicators": ["Unable to extract URL domain"]
            }

        # --------------------------------
        # IP address instead of domain
        # --------------------------------

        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        if re.match(ip_pattern, hostname):

            score += 25

            indicators.append(
                "URL uses an IP address instead of a domain"
            )

        # --------------------------------
        # URL shortening service
        # --------------------------------

        if hostname in URL_SHORTENERS:

            score += 20

            indicators.append(
                "URL shortening service detected"
            )

        # --------------------------------
        # Punycode
        # --------------------------------

        if "xn--" in hostname:

            score += 20

            indicators.append(
                "Punycode domain detected"
            )

        # --------------------------------
        # Suspicious TLD
        # --------------------------------

        if any(
            hostname.endswith(tld)
            for tld in SUSPICIOUS_TLDS
        ):

            score += 15

            indicators.append(
                "Suspicious top-level domain detected"
            )

        # --------------------------------
        # Very long URL
        # --------------------------------

        if len(url) > 150:

            score += 10

            indicators.append(
                "Unusually long URL detected"
            )

        # --------------------------------
        # Excessive subdomains
        # --------------------------------

        subdomain_count = hostname.count(".")

        if subdomain_count >= 4:

            score += 15

            indicators.append(
                "Excessive subdomains detected"
            )

        # --------------------------------
        # Suspicious keywords
        # --------------------------------

        suspicious_words = [
            "login",
            "verify",
            "verification",
            "secure",
            "account",
            "password",
            "update",
            "signin",
            "confirm"
        ]

        url_lower = url.lower()

        found_words = [
            word
            for word in suspicious_words
            if word in url_lower
        ]

        if found_words:

            score += min(
                20,
                len(found_words) * 5
            )

            indicators.append(
                "Suspicious keywords found in URL"
            )

        # --------------------------------
        # Sender / URL domain comparison
        # --------------------------------

        if sender_domain:

            sender_domain = sender_domain.lower().strip()

            if hostname != sender_domain:

                score += 10

                indicators.append(
                    "URL domain differs from sender domain"
                )

        # --------------------------------
        # Final classification
        # --------------------------------

        score = min(score, 100)

        if score >= 60:

            classification = "MALICIOUS"

        elif score >= 30:

            classification = "SUSPICIOUS"

        else:

            classification = "LOW RISK"

        return {
            "url": url,
            "domain": hostname,
            "score": score,
            "classification": classification,
            "indicators": indicators
        }

    except Exception as error:

        return {
            "url": url,
            "domain": None,
            "score": 0,
            "classification": "UNKNOWN",
            "indicators": [
                f"URL analysis error: {str(error)}"
            ]
        }


def analyze_urls(urls, sender_domain=None):

    results = []

    for url in urls:

        results.append(
            analyze_url(
                url,
                sender_domain
            )
        )

    return results