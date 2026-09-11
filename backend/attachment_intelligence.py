import os


HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".scr",
    ".vbs",
    ".ps1",
    ".msi",
    ".dll",
    ".jar"
}


MACRO_CAPABLE_EXTENSIONS = {
    ".doc",
    ".docm",
    ".xls",
    ".xlsm",
    ".ppt",
    ".pptm"
}


ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z"
}


def analyze_attachment(attachment):

    filename = attachment.get(
        "filename",
        "Unknown"
    )

    content_type = attachment.get(
        "content_type",
        "Unknown"
    )

    indicators = []
    score = 0

    extension = os.path.splitext(
        filename
    )[1].lower()

    # -----------------------------
    # High-risk executable files
    # -----------------------------

    if extension in HIGH_RISK_EXTENSIONS:

        score += 50

        indicators.append(
            "Executable or script attachment detected"
        )

    # -----------------------------
    # Macro-capable documents
    # -----------------------------

    elif extension in MACRO_CAPABLE_EXTENSIONS:

        score += 25

        indicators.append(
            "Macro-capable document detected"
        )

    # -----------------------------
    # Archive files
    # -----------------------------

    elif extension in ARCHIVE_EXTENSIONS:

        score += 15

        indicators.append(
            "Archive attachment detected"
        )

    # -----------------------------
    # Double extension detection
    # Example: invoice.pdf.exe
    # -----------------------------

    filename_lower = filename.lower()

    dangerous_extensions = (
        HIGH_RISK_EXTENSIONS
        | MACRO_CAPABLE_EXTENSIONS
    )

    matching_extensions = [
        ext
        for ext in dangerous_extensions
        if ext in filename_lower
    ]

    if (
        len(matching_extensions) >= 2
        or (
            "." in filename_lower
            and extension in HIGH_RISK_EXTENSIONS
        )
    ):

        score += 25

        indicators.append(
            "Potential double-extension filename detected"
        )

    # -----------------------------
    # Final classification
    # -----------------------------

    score = min(score, 100)

    if score >= 60:

        classification = "MALICIOUS"

    elif score >= 30:

        classification = "SUSPICIOUS"

    else:

        classification = "LOW RISK"

    return {
        "filename": filename,
        "content_type": content_type,
        "extension": extension,
        "score": score,
        "classification": classification,
        "indicators": indicators
    }


def analyze_attachments(attachments):

    results = []

    for attachment in attachments:

        results.append(
            analyze_attachment(
                attachment
            )
        )

    return results