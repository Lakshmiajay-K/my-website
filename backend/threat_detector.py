from backend.url_intelligence import analyze_urls
from backend.forensic_engine import create_forensic_timeline
from backend.dns_intelligence import analyze_domain
from backend.sender_intelligence import analyze_sender
from backend.ip_intelligence import analyze_ip
from backend.attachment_intelligence import analyze_attachments
from backend.authentication_intelligence import analyze_authentication
from backend.impersonation_intelligence import analyze_impersonation
from backend.content_intelligence import analyze_content
from backend.correlation_intelligence import analyze_correlation
from backend.evidence_engine import calculate_confidence


def get_address(address_list):

    if not address_list:
        return None

    if len(address_list[0]) > 1:
        return address_list[0][1].lower().strip()

    return None


def get_domain(address):

    if not address or "@" not in address:
        return None

    return address.split("@")[-1].lower().strip()


def analyze_email(email_data):

    score = 0

    indicators = []


    risk_breakdown = {
        "Authentication": 0,
        "Sender": 0,
        "Header": 0,
        "URL": 0,
        "Domain": 0,
        "Language": 0,
        "Attachment": 0,
        "IP": 0,
        "Impersonation": 0,
        "Correlation": 0
    }


    # =================================================
    # 1. Authentication
    # =================================================

    authentication_analysis = analyze_authentication(
        email_data.get(
            "authentication_results",
            ""
        )
    )

    authentication_score = authentication_analysis.get(
        "total_score",
        0
    )

    score += authentication_score

    risk_breakdown["Authentication"] = authentication_score


    auth = email_data.get(
        "authentication_results",
        ""
    ).lower()


    if "spf=fail" in auth:
        indicators.append(
            "SPF authentication failed"
        )

    if "dkim=fail" in auth:
        indicators.append(
            "DKIM authentication failed"
        )

    if "dmarc=fail" in auth:
        indicators.append(
            "DMARC authentication failed"
        )


    # =================================================
    # 2. Sender
    # =================================================

    sender_analysis = analyze_sender(
        email_data
    )

    sender_score = sender_analysis.get(
        "score",
        0
    )

    score += sender_score

    risk_breakdown["Sender"] = sender_score


    indicators.extend(
        sender_analysis.get(
            "indicators",
            []
        )
    )


    sender_address = get_address(
        email_data.get(
            "from",
            []
        )
    )

    sender_domain = get_domain(
        sender_address
    )


    # =================================================
    # 3. Header / Reply-To
    # =================================================

    reply_to_address = get_address(
        email_data.get(
            "reply_to",
            []
        )
    )

    reply_to_domain = get_domain(
        reply_to_address
    )


    if (
        sender_address
        and reply_to_address
        and sender_address != reply_to_address
    ):

        score += 20

        risk_breakdown["Header"] += 20

        indicators.append(
            "From and Reply-To addresses do not match"
        )


    # =================================================
    # 4. URL Intelligence
    # =================================================

    url_analysis = analyze_urls(
        email_data.get(
            "urls",
            []
        ),
        sender_domain
    )


    url_total = sum(
        result.get(
            "score",
            0
        )
        for result in url_analysis
    )

    url_total = min(
        url_total,
        100
    )

    score += url_total

    risk_breakdown["URL"] = url_total


    for result in url_analysis:

        indicators.extend(
            result.get(
                "indicators",
                []
            )
        )


    # =================================================
    # 5. Domain Intelligence
    # =================================================

    domain_analysis = []

    analyzed_domains = set()


    for result in url_analysis:

        domain = result.get(
            "domain"
        )

        if (
            domain
            and domain not in analyzed_domains
        ):

            analyzed_domains.add(
                domain
            )

            analysis = analyze_domain(
                domain
            )

            domain_analysis.append(
                analysis
            )


            indicators.extend(
                analysis.get(
                    "indicators",
                    []
                )
            )


    domain_total = sum(
        result.get(
            "score",
            0
        )
        for result in domain_analysis
    )

    domain_total = min(
        domain_total,
        100
    )

    score += domain_total

    risk_breakdown["Domain"] = domain_total


    # =================================================
    # 6. Advanced Impersonation
    # =================================================

    impersonation_analysis = []

    impersonation_domains = set()


    # Sender domain first
    if sender_domain:

        impersonation_domains.add(
            sender_domain
        )


    # URL domains
    for result in url_analysis:

        domain = result.get(
            "domain"
        )

        if domain:
            impersonation_domains.add(
                domain
            )


    display_name = None

    sender_list = email_data.get(
        "from",
        []
    )

    if sender_list and len(sender_list[0]) > 1:

        display_name = sender_list[0][0]


    for domain in impersonation_domains:

        result = analyze_impersonation(
            domain,
            sender_address,
            display_name
        )

        impersonation_analysis.append(
            result
        )


        if result.get("score", 0) > 0:

            score += result.get(
                "score",
                0
            )

            risk_breakdown["Impersonation"] += result.get(
                "score",
                0
            )


        indicators.extend(
            result.get(
                "indicators",
                []
            )
        )


    risk_breakdown["Impersonation"] = min(
        risk_breakdown["Impersonation"],
        100
    )


    # =================================================
    # 7. Attachments
    # =================================================

    attachment_analysis = analyze_attachments(
        email_data.get(
            "attachments",
            []
        )
    )


    attachment_total = sum(
        result.get(
            "score",
            0
        )
        for result in attachment_analysis
    )

    attachment_total = min(
        attachment_total,
        100
    )

    score += attachment_total

    risk_breakdown["Attachment"] = attachment_total


    for result in attachment_analysis:

        indicators.extend(
            result.get(
                "indicators",
                []
            )
        )


    # =================================================
    # 8. IP Intelligence
    # =================================================

    ip_analysis = analyze_ip(
        email_data.get(
            "sender_ip"
        )
    )


    ip_score = ip_analysis.get(
        "score",
        0
    )

    score += ip_score

    risk_breakdown["IP"] = ip_score


    indicators.extend(
        ip_analysis.get(
            "indicators",
            []
        )
    )


    # =================================================
    # 9. Phishing Content
    # =================================================

    content_analysis = analyze_content(
        email_data.get(
            "subject",
            ""
        ),
        email_data.get(
            "body",
            ""
        )
    )


    content_score = content_analysis.get(
        "score",
        0
    )

    score += content_score

    risk_breakdown["Language"] = content_score


    indicators.extend(
        content_analysis.get(
            "indicators",
            []
        )
    )


    # =================================================
    # 10. URL + Domain Correlation
    # =================================================

    correlation_analysis = analyze_correlation(
        sender_domain,
        url_analysis,
        domain_analysis,
        reply_to_domain
    )


    correlation_score = correlation_analysis.get(
        "score",
        0
    )

    score += correlation_score

    risk_breakdown["Correlation"] = correlation_score


    indicators.extend(
        correlation_analysis.get(
            "indicators",
            []
        )
    )


    # =================================================
    # 11. Final Threat Score
    # =================================================

    score = min(
        score,
        100
    )


    if score >= 60:

        classification = "MALICIOUS"

    elif score >= 30:

        classification = "SUSPICIOUS"

    else:

        classification = "SAFE"


    # =================================================
    # 12. Forensic Timeline
    # =================================================

    forensic_timeline = create_forensic_timeline(
        email_data
    )


    # =================================================
    # 13. Evidence Confidence
    # =================================================

    confidence = calculate_confidence(
        score,
        indicators,
        authentication_analysis,
        url_analysis,
        attachment_analysis,
        impersonation_analysis,
        content_analysis
    )


    # =================================================
    # 14. Final Result
    # =================================================

    return {

        "threat_score":
            score,

        "classification":
            classification,

        "confidence":
            confidence,

        "indicators":
            indicators,

        "sender_analysis":
            sender_analysis,

        "ip_analysis":
            ip_analysis,

        "url_analysis":
            url_analysis,

        "domain_analysis":
            domain_analysis,

        "attachment_analysis":
            attachment_analysis,

        "authentication_analysis":
            authentication_analysis,

        "impersonation_analysis":
            impersonation_analysis,

        "content_analysis":
            content_analysis,

        "correlation_analysis":
            correlation_analysis,

        "forensic_timeline":
            forensic_timeline,

        "risk_breakdown":
            risk_breakdown
    }