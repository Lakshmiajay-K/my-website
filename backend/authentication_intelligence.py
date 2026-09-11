import re


def analyze_authentication(authentication_results):

    result = {
        "spf": {
            "status": "UNKNOWN",
            "score": 0,
            "explanation": "SPF result not available"
        },
        "dkim": {
            "status": "UNKNOWN",
            "score": 0,
            "explanation": "DKIM result not available"
        },
        "dmarc": {
            "status": "UNKNOWN",
            "score": 0,
            "explanation": "DMARC result not available"
        },
        "overall_status": "UNKNOWN",
        "total_score": 0
    }

    if not authentication_results:
        return result

    auth = authentication_results.lower()

    # -------------------------
    # SPF
    # -------------------------

    match = re.search(
        r"spf\s*=\s*([a-zA-Z]+)",
        auth
    )

    if match:

        status = match.group(1).upper()

        result["spf"]["status"] = status

        if status == "PASS":

            result["spf"]["explanation"] = (
                "The sending server is authorized by the sender's SPF policy."
            )

        elif status in {"FAIL", "SOFTFAIL"}:

            result["spf"]["score"] = 25

            result["spf"]["explanation"] = (
                "The sending server failed the sender's SPF authorization check."
            )

        else:

            result["spf"]["explanation"] = (
                "SPF returned a non-standard or inconclusive result."
            )

    # -------------------------
    # DKIM
    # -------------------------

    match = re.search(
        r"dkim\s*=\s*([a-zA-Z]+)",
        auth
    )

    if match:

        status = match.group(1).upper()

        result["dkim"]["status"] = status

        if status == "PASS":

            result["dkim"]["explanation"] = (
                "The email's DKIM signature was successfully verified."
            )

        elif status == "FAIL":

            result["dkim"]["score"] = 20

            result["dkim"]["explanation"] = (
                "The email's DKIM signature failed verification."
            )

        else:

            result["dkim"]["explanation"] = (
                "DKIM returned a non-standard or inconclusive result."
            )

    # -------------------------
    # DMARC
    # -------------------------

    match = re.search(
        r"dmarc\s*=\s*([a-zA-Z]+)",
        auth
    )

    if match:

        status = match.group(1).upper()

        result["dmarc"]["status"] = status

        if status == "PASS":

            result["dmarc"]["explanation"] = (
                "The message passed the sender's DMARC authentication policy."
            )

        elif status == "FAIL":

            result["dmarc"]["score"] = 20

            result["dmarc"]["explanation"] = (
                "The message failed DMARC alignment or authentication."
            )

        else:

            result["dmarc"]["explanation"] = (
                "DMARC returned a non-standard or inconclusive result."
            )

    # -------------------------
    # Overall status
    # -------------------------

    statuses = [
        result["spf"]["status"],
        result["dkim"]["status"],
        result["dmarc"]["status"]
    ]

    if all(status == "PASS" for status in statuses):

        result["overall_status"] = "AUTHENTICATED"

    elif any(
        status in {"FAIL", "SOFTFAIL"}
        for status in statuses
    ):

        result["overall_status"] = "FAILED"

    else:

        result["overall_status"] = "PARTIAL"

    result["total_score"] = (
        result["spf"]["score"]
        + result["dkim"]["score"]
        + result["dmarc"]["score"]
    )

    return result