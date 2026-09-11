import re
from email.utils import parsedate_to_datetime
from datetime import timezone


IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"


def extract_received_hops(email_data):

    received_headers = email_data.get(
        "received_headers",
        []
    )

    hops = []

    for index, header in enumerate(
        received_headers,
        start=1
    ):

        ip_match = re.search(
            IP_PATTERN,
            header
        )

        ip = (
            ip_match.group()
            if ip_match
            else None
        )

        timestamp = None

        if ";" in header:

            date_part = header.rsplit(
                ";",
                1
            )[1].strip()

            try:

                dt = parsedate_to_datetime(
                    date_part
                )

                if dt.tzinfo is None:

                    dt = dt.replace(
                        tzinfo=timezone.utc
                    )

                timestamp = dt.isoformat()

            except Exception:

                pass

        hops.append({
            "hop": index,
            "ip": ip,
            "timestamp": timestamp,
            "raw": header
        })

    return hops


def create_forensic_timeline(email_data):

    timeline = []


    # =========================
    # Email Date
    # =========================

    email_date = email_data.get(
        "date",
        ""
    )

    if email_date:

        try:

            dt = parsedate_to_datetime(
                email_date
            )

            if dt.tzinfo is None:

                dt = dt.replace(
                    tzinfo=timezone.utc
                )

            timeline.append({
                "timestamp": dt.isoformat(),
                "event": "Email date identified",
                "evidence": email_date
            })

        except Exception:

            pass


    # =========================
    # Received Header Hops
    # =========================

    hops = extract_received_hops(
        email_data
    )


    for hop in hops:

        timeline.append({

            "timestamp": hop["timestamp"],

            "event":
                f"Mail hop {hop['hop']} identified",

            "evidence": {

                "ip": hop["ip"],

                "raw_header":
                    hop["raw"]
            }
        })


    # =========================
    # Delivery Path Summary
    # =========================

    if hops:

        timeline.append({

            "timestamp": None,

            "event":
                "Email delivery path analyzed",

            "evidence": {

                "total_hops":
                    len(hops),

                "ips":
                    [
                        hop["ip"]
                        for hop in hops
                        if hop["ip"]
                    ]
            }
        })


    # =========================
    # Sender IP
    # =========================

    sender_ip = email_data.get(
        "sender_ip"
    )

    if sender_ip:

        timeline.append({

            "timestamp": None,

            "event":
                "Sender IP identified",

            "evidence":
                sender_ip
        })


    # =========================
    # Sender
    # =========================

    sender = email_data.get(
        "from",
        []
    )

    if sender:

        timeline.append({

            "timestamp": None,

            "event":
                "Sender identified",

            "evidence":
                str(sender)
        })


    # =========================
    # Reply-To
    # =========================

    reply_to = email_data.get(
        "reply_to",
        []
    )

    if reply_to:

        timeline.append({

            "timestamp": None,

            "event":
                "Reply-To identified",

            "evidence":
                str(reply_to)
        })


    # =========================
    # Authentication Results
    # =========================

    auth = email_data.get(
        "authentication_results",
        ""
    ).lower()


    for name in [
        "spf",
        "dkim",
        "dmarc"
    ]:

        match = re.search(
            rf"{name}\s*=\s*(\w+)",
            auth
        )

        if match:

            timeline.append({

                "timestamp": None,

                "event":
                    f"{name.upper()} authentication result",

                "evidence":
                    match.group(1).upper()
            })


    # =========================
    # URLs
    # =========================

    for url in email_data.get(
        "urls",
        []
    ):

        timeline.append({

            "timestamp": None,

            "event":
                "URL extracted from email",

            "evidence":
                url
        })


    # =========================
    # Attachments
    # =========================

    for attachment in email_data.get(
        "attachments",
        []
    ):

        filename = attachment.get(
            "filename",
            "Unknown"
        )

        content_type = attachment.get(
            "content_type",
            "Unknown"
        )

        timeline.append({

            "timestamp": None,

            "event":
                "Attachment detected",

            "evidence":
                f"{filename} ({content_type})"
        })


    return timeline