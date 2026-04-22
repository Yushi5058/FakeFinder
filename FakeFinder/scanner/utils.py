import email
import re

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


def sanitize_url(url):
    """Sanitize URLs to prevent XSS when rendered."""
    url = url.strip()
    if url.startswith(("javascript:", "data:", "vbscript:")):
        return ""
    return url


def get_text_from_part(p):
    payload = p.get_payload(decode=True)
    if isinstance(payload, bytes):
        charset = p.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="ignore")
        except LookupError:
            return payload.decode("utf-8", errors="ignore")
    elif isinstance(payload, str):
        return payload
    return ""


def parse_eml_in_memory(file_obj):
    """
    Takes an in-memory Django file object, parses the .eml data,
    and returns a dictionary of ML-ready features without saving to disk.
    """
    file_obj.seek(0, 2)
    if file_obj.tell() > MAX_FILE_SIZE:
        raise ValueError("File too large")
    file_obj.seek(0)

    header = file_obj.read(6)
    file_obj.seek(0)
    if not (header.startswith(b"From:") or b"\nFrom:" in header):
        raise ValueError("Invalid email format")
    # 1. Read the file completely in memory
    msg = email.message_from_bytes(file_obj.read())

    # 2. Extract Sender Domain
    sender = msg.get("From", "")
    sender_domain = ""
    if "@" in sender:
        # Extracts "badguy.com" from "Hacker <admin@badguy.com>"
        domain_match = re.search(r"@([\w.-]+)", sender)
        if domain_match:
            sender_domain = domain_match.group(1).strip(">")

    # 3. Extract the Body Text
    body_text = ""
    if msg.is_multipart():
        # Loop through email parts (handles emails that have both HTML and Plain Text)
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition"))

            # We only want text, no attachments
            if (
                content_type in ["text/plain", "text/html"]
                and "attachment" not in disposition
            ):
                try:
                    body_text += get_text_from_part(part) + " "
                except Exception as e:
                    print(f"Failed to parse part: {e}")
    else:
        try:
            body_text = get_text_from_part(msg)
        except Exception as e:
            print(f"Failed to parse single payload: {e}")

    # Clean up the body text (remove excessive newlines/spaces)
    body_text = re.sub(r"\s+", " ", body_text).strip()

    # 4. Extract URLs from the body
    # Standard Regex to find http/https links
    url_pattern = r'(https?://[^\s>"\']+)'
    extracted_urls = list(
        set(re.findall(url_pattern, body_text))
    )  # set() removes duplicates

    return {
        "sender_domain": sender_domain,
        "body_text": body_text,
        "urls": [url for url in (sanitize_url(url) for url in extracted_urls) if url],
    }
