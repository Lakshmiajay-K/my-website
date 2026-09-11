from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
import re


def extract_urls(text):
    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+"
    return re.findall(pattern, text)


def parse_email(file_path):
    with open(file_path, "rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    body = ""
    attachments = []

    if message.is_multipart():
        for part in message.walk():

            content_type = part.get_content_type()

            if part.is_attachment():
                filename = part.get_filename()

                if filename:
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type
                    })

            elif content_type == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    pass

    else:
        try:
            body = message.get_content()
        except Exception:
            body = ""

    from_address = getaddresses(
        [message.get("From", "")]
    )

    reply_to = getaddresses(
        [message.get("Reply-To", "")]
    )

    urls = extract_urls(body)

    return {
        "from": from_address,
        "to": message.get("To", ""),
        "subject": message.get("Subject", ""),
        "date": message.get("Date", ""),
        "reply_to": reply_to,
        "received_headers": message.get_all("Received", []),
        "sender_ip": extract_sender_ip(message),
        "authentication_results": message.get(
            "Authentication-Results", ""
        ),
        "urls": urls,
        "attachments": attachments,
        "body": body
    }


def extract_sender_ip(message):
    received_headers = message.get_all("Received", [])

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    for header in received_headers:
        match = re.search(ip_pattern, header)

        if match:
            return match.group()

    return None