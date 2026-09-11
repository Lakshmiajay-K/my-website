def analyze_correlation(
    sender_domain,
    url_analysis,
    domain_analysis,
    reply_to_domain=None
):

    indicators = []
    evidence = []

    score = 0


    url_count = len(
        url_analysis or []
    )

    domain_count = len(
        domain_analysis or []
    )


    # -------------------------------------------------
    # Sender domain vs URL domain
    # -------------------------------------------------

    for url_result in url_analysis or []:

        url_domain = url_result.get(
            "domain"
        )

        if (
            sender_domain
            and url_domain
            and url_domain != sender_domain
        ):

            score += 10

            indicators.append(
                "Email sender domain differs from linked URL domain"
            )

            evidence.append({
                "type": "SENDER_URL_MISMATCH",
                "sender_domain": sender_domain,
                "url_domain": url_domain
            })

            break


    # -------------------------------------------------
    # Reply-To vs sender domain
    # -------------------------------------------------

    if (
        sender_domain
        and reply_to_domain
        and sender_domain != reply_to_domain
    ):

        score += 10

        indicators.append(
            "Reply-To domain differs from sender domain"
        )

        evidence.append({
            "type": "SENDER_REPLYTO_MISMATCH",
            "sender_domain": sender_domain,
            "reply_to_domain": reply_to_domain
        })


    # -------------------------------------------------
    # Suspicious URL + DNS problem
    # -------------------------------------------------

    for url_result in url_analysis or []:

        url_score = url_result.get(
            "score",
            0
        )

        for domain_result in domain_analysis or []:

            domain_score = domain_result.get(
                "score",
                0
            )

            if (
                url_score >= 30
                and domain_score >= 30
            ):

                score += 10

                indicators.append(
                    "URL risk is reinforced by suspicious domain intelligence"
                )

                evidence.append({
                    "type": "URL_DOMAIN_CORRELATION",
                    "url_score": url_score,
                    "domain_score": domain_score
                })

                break

        if score >= 30:
            break


    # -------------------------------------------------
    # Multiple linked domains
    # -------------------------------------------------

    unique_domains = {
        result.get("domain")
        for result in url_analysis or []
        if result.get("domain")
    }

    if len(unique_domains) >= 3:

        score += 5

        indicators.append(
            "Email contains links to multiple external domains"
        )

        evidence.append({
            "type": "MULTIPLE_EXTERNAL_DOMAINS",
            "domain_count": len(unique_domains)
        })


    # -------------------------------------------------
    # Combined URL + DNS risk
    # -------------------------------------------------

    combined_risk = 0

    for result in url_analysis or []:
        combined_risk += result.get(
            "score",
            0
        )

    for result in domain_analysis or []:
        combined_risk += result.get(
            "score",
            0
        )

    combined_risk = min(
        combined_risk,
        100
    )


    score = min(
        score,
        40
    )


    if score >= 30:

        classification = "HIGH CORRELATION"

    elif score >= 15:

        classification = "SUSPICIOUS CORRELATION"

    elif score > 0:

        classification = "LOW CORRELATION"

    else:

        classification = "NO CORRELATION"


    return {
        "score": score,
        "classification": classification,
        "combined_url_domain_risk": combined_risk,
        "indicators": indicators,
        "evidence": evidence,
        "url_count": url_count,
        "domain_count": domain_count
    }