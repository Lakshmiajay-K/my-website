import re

FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "proton.me",
    "protonmail.com"
}

SUSPICIOUS_SENDER_WORDS = {
    "verify",
    "billing",
    "payment",
    "account",
    "password",
    "support"
}


def analyze_sender(email_data):

    indicators = []
    score = 0

    sender = email_data.get("from", [])

    if not sender:
        return {
            "sender": None,
            "domain": None,
            "score": 0,
            "classification": "UNKNOWN",
            "indicators": []
        }

    sender_address = (
        sender[0][1]
        if len(sender[0]) > 1
        else ""
    )

    sender_address = sender_address.lower().strip()

    # Invalid sender
    if "@" not in sender_address:

        score += 30

        indicators.append(
            "Invalid or malformed sender address"
        )

        return {
            "sender": sender_address,
            "domain": None,
            "score": score,
            "classification": "SUSPICIOUS",
            "indicators": indicators
        }

    # Extract domain
    domain = sender_address.split("@")[-1]

    # Local part
    local_part = sender_address.split("@")[0]

    # Free email provider
    if domain in FREE_EMAIL_PROVIDERS:

        score += 5

        indicators.append(
            "Sender uses a free email provider"
        )

    # Suspicious sender words
    found_words = [
        word
        for word in SUSPICIOUS_SENDER_WORDS
        if word in local_part
    ]

    if found_words:

        score += 5

        indicators.append(
            "Sender address contains security-sensitive keywords"
        )

    # Excessive numbers
    digit_count = len(
        re.findall(r"\d", local_part)
    )

    if digit_count >= 4:

        score += 10

        indicators.append(
            "Sender address contains an unusual number of digits"
        )

    # Very long sender address
    if len(sender_address) > 60:

        score += 10

        indicators.append(
            "Unusually long sender address detected"
        )

    # Final score
    score = min(score, 100)

    if score >= 60:

        classification = "MALICIOUS"

    elif score >= 30:

        classification = "SUSPICIOUS"

    else:

        classification = "LOW RISK"

    return {
        "sender": sender_address,
        "domain": domain,
        "score": score,
        "classification": classification,
        "indicators": indicators
    }