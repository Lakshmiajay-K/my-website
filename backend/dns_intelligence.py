import dns.resolver


def resolve_domain(domain):

    result = {
        "domain": domain,
        "a_records": [],
        "mx_records": [],
        "status": "UNKNOWN",
        "indicators": []
    }

    if not domain:
        return result

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    # A records
    try:
        answers = resolver.resolve(domain, "A")

        result["a_records"] = [
            answer.to_text()
            for answer in answers
            if answer.to_text()
        ]

    except dns.resolver.NXDOMAIN:
        result["indicators"].append(
            "Domain does not exist according to DNS"
        )

    except dns.resolver.NoAnswer:
        result["indicators"].append(
            "Domain exists but has no A record"
        )

    except dns.resolver.NoNameservers:
        result["indicators"].append(
            "No authoritative DNS nameserver available"
        )

    except dns.exception.DNSException as error:
        result["indicators"].append(
            f"A record lookup failed: {str(error)}"
        )

    # MX records
    try:
        answers = resolver.resolve(domain, "MX")

        mx_records = []

        for answer in answers:
            mx_host = answer.exchange.to_text().rstrip(".")

            if mx_host:
                mx_records.append(mx_host)

        result["mx_records"] = mx_records

    except dns.resolver.NoAnswer:
        pass

    except dns.resolver.NXDOMAIN:
        pass

    except dns.exception.DNSException:
        pass

    # Determine status
    if result["a_records"] or result["mx_records"]:
        result["status"] = "RESOLVED"

    elif any(
        "does not exist" in indicator
        for indicator in result["indicators"]
    ):
        result["status"] = "UNRESOLVED"

    else:
        result["status"] = "LOOKUP FAILED"

    return result


def analyze_domain(domain):

    result = resolve_domain(domain)

    score = 0

    if result["status"] == "UNRESOLVED":

        score += 30

        result["indicators"].append(
            "Domain could not be resolved through DNS"
        )

    elif result["status"] == "LOOKUP FAILED":

        # Temporary DNS/network failure should not
        # be treated as proof of a malicious domain.
        result["indicators"].append(
            "DNS lookup could not be completed"
        )

    if (
        result["status"] == "RESOLVED"
        and not result["mx_records"]
    ):

        result["indicators"].append(
            "No MX record found"
        )

    result["score"] = min(score, 100)

    if score >= 30:
        result["classification"] = "SUSPICIOUS"

    else:
        result["classification"] = "LOW RISK"

    return result