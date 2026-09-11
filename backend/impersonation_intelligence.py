import re


COMMON_BRANDS = {
    "google.com": "Google",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "amazon.com": "Amazon",
    "paypal.com": "PayPal",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "linkedin.com": "LinkedIn",
    "github.com": "GitHub",
    "netflix.com": "Netflix",
    "adobe.com": "Adobe",
    "dropbox.com": "Dropbox",
    "docusign.com": "DocuSign",
    "zoom.us": "Zoom"
}


CHARACTER_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b"
}


SUSPICIOUS_DOMAIN_WORDS = {
    "login",
    "secure",
    "security",
    "verify",
    "verification",
    "account",
    "support",
    "alert",
    "update",
    "signin",
    "password",
    "billing",
    "payment"
}


def normalize_domain(domain):
    if not domain:
        return ""

    domain = domain.lower().strip()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def get_base_name(domain):
    domain = normalize_domain(domain)
    parts = domain.split(".")

    return parts[0] if parts else ""


def normalize_lookalike(domain):

    domain = normalize_domain(domain)
    parts = domain.split(".")

    if len(parts) < 2:
        return domain

    name = parts[0]

    for fake, real in CHARACTER_MAP.items():
        name = name.replace(fake, real)

    return name + "." + ".".join(parts[1:])


def levenshtein_distance(first, second):

    rows = len(first) + 1
    columns = len(second) + 1

    matrix = [
        [0] * columns
        for _ in range(rows)
    ]

    for i in range(rows):
        matrix[i][0] = i

    for j in range(columns):
        matrix[0][j] = j

    for i in range(1, rows):

        for j in range(1, columns):

            cost = (
                0
                if first[i - 1] == second[j - 1]
                else 1
            )

            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            )

    return matrix[-1][-1]


def analyze_impersonation(
    domain,
    sender_address=None,
    display_name=None
):

    result = {
        "domain": domain,
        "sender": sender_address,
        "display_name": display_name,
        "is_lookalike": False,
        "matched_brand": None,
        "score": 0,
        "classification": "LOW RISK",
        "indicators": []
    }

    if not domain:
        return result

    domain = normalize_domain(domain)

    # -------------------------------------------------
    # Exact legitimate brand domain
    # -------------------------------------------------

    if domain in COMMON_BRANDS:

        result["matched_brand"] = COMMON_BRANDS[domain]

        return result


    # -------------------------------------------------
    # Character substitution
    # -------------------------------------------------

    normalized = normalize_lookalike(domain)

    for brand_domain, brand_name in COMMON_BRANDS.items():

        if normalized == brand_domain:

            result["is_lookalike"] = True
            result["matched_brand"] = brand_name
            result["score"] += 60

            result["indicators"].append(
                f"Domain resembles {brand_name} using character substitutions"
            )

            break


    # -------------------------------------------------
    # Similarity detection
    # -------------------------------------------------

    if not result["is_lookalike"]:

        domain_name = get_base_name(domain)

        for brand_domain, brand_name in COMMON_BRANDS.items():

            brand_part = get_base_name(
                brand_domain
            )

            distance = levenshtein_distance(
                domain_name,
                brand_part
            )

            maximum_length = max(
                len(domain_name),
                len(brand_part)
            )

            if maximum_length == 0:
                continue

            similarity = 1 - (
                distance / maximum_length
            )

            if (
                similarity >= 0.80
                and domain != brand_domain
            ):

                result["is_lookalike"] = True
                result["matched_brand"] = brand_name
                result["score"] += 50

                result["indicators"].append(
                    f"Domain is highly similar to {brand_name}"
                )

                break


    # -------------------------------------------------
    # Brand name inside sender address
    # -------------------------------------------------

    sender_lower = (
        sender_address or ""
    ).lower()

    display_lower = (
        display_name or ""
    ).lower()

    for brand_domain, brand_name in COMMON_BRANDS.items():

        brand_part = get_base_name(
            brand_domain
        )

        if (
            brand_part in sender_lower
            and domain != brand_domain
        ):

            result["matched_brand"] = brand_name

            result["score"] += 25

            result["indicators"].append(
                f"Sender address references {brand_name} but uses a different domain"
            )

            break

        if (
            brand_name.lower() in display_lower
            and domain != brand_domain
        ):

            result["matched_brand"] = brand_name

            result["score"] += 25

            result["indicators"].append(
                f"Display name references {brand_name} but sender domain differs"
            )

            break


    # -------------------------------------------------
    # Suspicious security-related domain words
    # -------------------------------------------------

    found_words = [
        word
        for word in SUSPICIOUS_DOMAIN_WORDS
        if word in domain
    ]

    if found_words:

        result["score"] += min(
            20,
            len(found_words) * 5
        )

        result["indicators"].append(
            "Domain contains security-sensitive keywords"
        )


    result["score"] = min(
        result["score"],
        100
    )


    if result["score"] >= 60:

        result["classification"] = "MALICIOUS"

    elif result["score"] >= 30:

        result["classification"] = "SUSPICIOUS"

    else:

        result["classification"] = "LOW RISK"


    return result