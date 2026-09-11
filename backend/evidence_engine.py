def calculate_confidence(
    threat_score,
    indicators,
    authentication_analysis,
    url_analysis,
    attachment_analysis,
    impersonation_analysis,
    content_analysis
):

    evidence_count = len(
        indicators or []
    )

    strong_evidence = 0


    # Authentication
    auth = authentication_analysis or {}

    for name in ["spf", "dkim", "dmarc"]:

        status = auth.get(
            name,
            {}
        ).get(
            "status",
            "UNKNOWN"
        )

        if status in {
            "FAIL",
            "SOFTFAIL"
        }:

            strong_evidence += 1


    # Suspicious URLs
    for result in url_analysis or []:

        if result.get("score", 0) >= 30:
            strong_evidence += 1


    # Dangerous attachments
    for result in attachment_analysis or []:

        if result.get("score", 0) >= 50:
            strong_evidence += 1


    # Impersonation
    for result in impersonation_analysis or []:

        if result.get("score", 0) >= 50:
            strong_evidence += 1


    # Content
    if (
        content_analysis
        and content_analysis.get("score", 0) >= 30
    ):

        strong_evidence += 1


    # -------------------------------------------------
    # Confidence calculation
    # -------------------------------------------------

    confidence = (
        evidence_count * 4
        + strong_evidence * 8
        + threat_score * 0.25
    )


    confidence = min(
        round(confidence),
        99
    )


    if confidence >= 80:

        level = "VERY HIGH"

    elif confidence >= 60:

        level = "HIGH"

    elif confidence >= 35:

        level = "MEDIUM"

    else:

        level = "LOW"


    return {
        "confidence_score": confidence,
        "confidence_level": level,
        "evidence_count": evidence_count,
        "strong_evidence_count": strong_evidence,
        "explanation": (
            "Confidence represents how strongly the available "
            "email evidence supports the current classification. "
            "It is not a guarantee that the email is malicious."
        )
    }