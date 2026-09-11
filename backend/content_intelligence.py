import re


URGENCY_PATTERNS = {
    "urgent",
    "immediately",
    "right away",
    "action required",
    "act now",
    "as soon as possible",
    "account locked",
    "account suspended",
    "security alert"
}


CREDENTIAL_PATTERNS = {
    "password",
    "passcode",
    "otp",
    "one time password",
    "login",
    "sign in",
    "username",
    "credentials",
    "verify your account"
}


FINANCIAL_PATTERNS = {
    "invoice",
    "payment",
    "refund",
    "bank",
    "credit card",
    "debit card",
    "transaction",
    "billing",
    "money",
    "wire transfer"
}


THREAT_PATTERNS = {
    "suspended",
    "blocked",
    "terminated",
    "legal action",
    "account will be closed",
    "unauthorized activity"
}


def find_matches(text, patterns):

    matches = []

    text = text.lower()

    for pattern in patterns:

        if pattern in text:

            matches.append(pattern)

    return matches


def analyze_content(subject, body):

    subject = subject or ""
    body = body or ""

    combined_text = (
        subject
        + " "
        + body
    ).lower()


    indicators = []

    categories = {}

    score = 0


    # Urgency
    urgency_matches = find_matches(
        combined_text,
        URGENCY_PATTERNS
    )

    categories["urgency"] = urgency_matches

    if urgency_matches:

        score += min(
            20,
            len(urgency_matches) * 5
        )

        indicators.append(
            "Urgency or pressure language detected"
        )


    # Credential requests
    credential_matches = find_matches(
        combined_text,
        CREDENTIAL_PATTERNS
    )

    categories["credentials"] = credential_matches

    if credential_matches:

        score += min(
            25,
            len(credential_matches) * 5
        )

        indicators.append(
            "Credential or account verification language detected"
        )


    # Financial requests
    financial_matches = find_matches(
        combined_text,
        FINANCIAL_PATTERNS
    )

    categories["financial"] = financial_matches

    if financial_matches:

        score += min(
            20,
            len(financial_matches) * 5
        )

        indicators.append(
            "Financial or payment-related language detected"
        )


    # Threat language
    threat_matches = find_matches(
        combined_text,
        THREAT_PATTERNS
    )

    categories["threats"] = threat_matches

    if threat_matches:

        score += min(
            20,
            len(threat_matches) * 5
        )

        indicators.append(
            "Threatening or account-consequence language detected"
        )


    # Excessive exclamation marks
    exclamation_count = combined_text.count("!")

    if exclamation_count >= 3:

        score += 5

        indicators.append(
            "Excessive exclamation marks detected"
        )


    # Excessive uppercase text
    letters = [
        char
        for char in subject + " " + body
        if char.isalpha()
    ]

    if len(letters) >= 20:

        uppercase_count = sum(
            1
            for char in letters
            if char.isupper()
        )

        uppercase_ratio = (
            uppercase_count / len(letters)
        )

        if uppercase_ratio >= 0.60:

            score += 5

            indicators.append(
                "Unusually high uppercase text detected"
            )


    score = min(
        score,
        100
    )


    if score >= 60:

        classification = "MALICIOUS"

    elif score >= 30:

        classification = "SUSPICIOUS"

    elif score > 0:

        classification = "LOW RISK"

    else:

        classification = "CLEAN"


    return {
        "score": score,
        "classification": classification,
        "indicators": indicators,
        "categories": categories
    }