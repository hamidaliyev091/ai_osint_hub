"""Parse h8mail output into structured breach entities."""

import re
from hub.cooking import extract_emails


def parse(raw_stdout: str, target_email: str = "") -> list[dict]:
    """Parse h8mail CLI output.

    h8mail outputs breach information for queried emails.
    Common output patterns vary by version. We handle the broadest patterns.

    Returns list of breach entities with any exposed fields.
    """
    entities = []

    # Strip ANSI escape codes that tools like h8mail emit with --no-color flag ignored
    # Pattern: \x1b[...m (color codes), \x1b[0m (reset), etc.
    raw_stdout = re.sub(r'\x1b\[[0-9;]*m', '', raw_stdout)

    # Detect breach names — often in headers or line prefixes
    breach_patterns = [
        r'(?:breach|leak|database):\s*(.+?)(?:\n|$)',
        r'\[(.*?)\]\s*(?:breach|leak)',
        r'(Collection\s*#?\d+)',
        r'(Exploit\.in)',
        r'(AntiPublic)',
        r'(LinkedIn\s*\d{4})',
        r'(Adobe\s*\d{4})',
        r'(Dropbox\s*\d{4})',
        r'(MySpace\s*\d{4})',
        r'(Tumblr\s*\d{4})',
        r'(Twitter\s*\d{4})',
        r'(Canva\s*\d{4})',
        r'(Zynga\s*\d{4})',
        r'(Dubsmash\s*\d{4})',
        r'(Deezer\s*\d{4})',
    ]

    found_breaches = set()
    for pattern in breach_patterns:
        for m in re.finditer(pattern, raw_stdout, re.IGNORECASE):
            name = m.group(1).strip()
            if name and len(name) > 2 and name not in found_breaches:
                found_breaches.add(name)

    # Also check for known breach names by keyword
    lower_output = raw_stdout.lower()
    known_breaches = [
        "collection #1", "collection 1", "exploit.in", "antipublic",
        "linkedin", "adobe", "dropbox", "myspace", "tumblr", "twitter",
        "canva", "zynga", "dubsmash", "deezer", "yahoo", "equifax",
        "marriott", "experian", "capital one",
    ]
    for breach in known_breaches:
        if breach in lower_output and breach not in found_breaches:
            found_breaches.add(breach.title())

    # Extract any emails in output
    emails = extract_emails(raw_stdout)

    # Build entities
    for breach_name in found_breaches:
        entity = {
            "type": "breach",
            "value": breach_name.lower().strip(),
            "confidence": 0.85,
            "sources": [f"h8mail:{target_email}"],
            "source": "tool_output",
            "metadata": {
                "email_target": target_email,
                "breach_name": breach_name,
            },
        }

        # Check for credential indicators
        if re.search(r'(?:password|passwd|hash|bcrypt|sha\d+|md5|pbkdf2|scrypt)',
                     raw_stdout, re.IGNORECASE):
            entity["metadata"]["credentials_exposed"] = True
            entity["confidence"] = 0.95  # Higher confidence when credentials found

        entities.append(entity)

    # If we found emails in the output, add them as separate entities
    for email in emails:
        if email != target_email:
            entities.append({
                "type": "email",
                "value": email.lower(),
                "confidence": 0.80,
                "sources": [f"h8mail:{target_email}"],
                "source": "tool_output",
                "metadata": {"found_in_breach_context": True},
            })

    return entities
