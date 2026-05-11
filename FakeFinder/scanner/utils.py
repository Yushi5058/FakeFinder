import email
import re
from email.header import decode_header as _decode_header

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


def _header_to_str(value) -> str:
    """Decode an email header value (str or Header object) to a plain unicode string."""
    if not value:
        return ""
    decoded_parts = _decode_header(str(value))
    result = []
    for raw, charset in decoded_parts:
        if isinstance(raw, bytes):
            result.append(raw.decode(charset or "utf-8", errors="replace"))
        else:
            result.append(raw)
    return " ".join(result)


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
        raise ValueError("Fichier trop volumineux (max 10 Mo).")
    file_obj.seek(0)

    # Read enough bytes to detect at least one RFC 2822 header field
    header_sample = file_obj.read(512)
    file_obj.seek(0)
    if not re.search(rb'(?i)(from|to|subject|mime-version|received|date|content-type|message-id)\s*:', header_sample):
        raise ValueError("Format email invalide.")
    # 1. Read the file completely in memory
    msg = email.message_from_bytes(file_obj.read())

    # 2. Extract Sender Domain, full email address, and Subject
    sender  = _header_to_str(msg.get("From", ""))
    subject = _header_to_str(msg.get("Subject", ""))
    sender_domain = ""
    sender_email  = ""
    if "@" in sender:
        email_match = re.search(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", sender)
        if email_match:
            sender_email  = email_match.group(0)
            sender_domain = sender_email.split("@", 1)[1]

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
        "sender_email":  sender_email,
        "subject":       subject,
        "body_text":     body_text,
        "urls": [url for url in (sanitize_url(url) for url in extracted_urls) if url],
    }
