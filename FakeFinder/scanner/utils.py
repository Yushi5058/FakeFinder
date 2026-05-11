import email
import re
import logging
from email.header import decode_header as _decode_header

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# More robust email regex
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+")

# Standard Regex to find http/https links
URL_PATTERN = re.compile(r'(https?://[^\s>"\']+)')


def _header_to_str(value) -> str:
    """Decode an email header value (str or Header object) to a plain unicode string."""
    if not value:
        return ""
    try:
        decoded_parts = _decode_header(str(value))
        result = []
        for raw, charset in decoded_parts:
            if isinstance(raw, bytes):
                result.append(raw.decode(charset or "utf-8", errors="replace"))
            else:
                result.append(raw)
        return " ".join(result)
    except Exception as e:
        logger.warning(f"Failed to decode header: {e}")
        return str(value)


def sanitize_url(url):
    """Sanitize URLs to prevent XSS when rendered."""
    url = url.strip()
    if url.lower().startswith(("javascript:", "data:", "vbscript:")):
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
    file_size = file_obj.tell()
    if file_size > MAX_FILE_SIZE:
        raise ValueError("Fichier trop volumineux (max 10 Mo).")
    file_obj.seek(0)

    # Read enough bytes to detect at least one RFC 2822 header field
    header_sample = file_obj.read(512)
    file_obj.seek(0)
    if not re.search(rb'(?i)(from|to|subject|mime-version|received|date|content-type|message-id)\s*:', header_sample):
        raise ValueError("Format email invalide.")
    
    # 1. Read the file completely in memory
    try:
        msg = email.message_from_bytes(file_obj.read())
    except Exception as e:
        logger.error(f"Failed to parse email from bytes: {e}")
        raise ValueError("Erreur lors de la lecture du fichier email.")

    # 2. Extract Sender Domain, full email address, and Subject
    sender  = _header_to_str(msg.get("From", ""))
    subject = _header_to_str(msg.get("Subject", ""))
    sender_domain = ""
    sender_email  = ""
    
    email_match = EMAIL_REGEX.search(sender)
    if email_match:
        sender_email  = email_match.group(0)
        if "@" in sender_email:
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
                    logger.debug(f"Failed to parse part: {e}")
    else:
        try:
            body_text = get_text_from_part(msg)
        except Exception as e:
            logger.debug(f"Failed to parse single payload: {e}")

    # Clean up the body text (remove excessive newlines/spaces)
    body_text = re.sub(r"\s+", " ", body_text).strip()

    # 4. Extract URLs from the body
    extracted_urls = list(
        set(URL_PATTERN.findall(body_text))
    )  # set() removes duplicates

    return {
        "sender_domain": sender_domain,
        "sender_email":  sender_email,
        "subject":       subject,
        "body_text":     body_text,
        "urls": [url for url in (sanitize_url(url) for url in extracted_urls) if url],
    }
