"""Parse holehe output into structured service entities."""

import re
from hub.cooking import extract_urls, extract_usernames_from_urls


def parse(raw_stdout: str, target: str = "") -> list[dict]:
    """Parse holehe CLI output.

    Holehe outputs lines like:
        [+] twitter.com
        [-] instagram.com
        [+] github.com

    Returns list of service entities with registration status.
    """
    entities = []
    urls_found = []

    for line in raw_stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Match [+] service or [-] service
        m = re.match(r'^\[([+-X?])\]\s+(.+?)(?:\s*$)', line)
        if m:
            status_char = m.group(1)
            service_name = m.group(2).strip()

            registered = status_char == "+"
            confidence = 0.95 if registered else 0.70

            service_url = ""
            # Try to construct URL
            if "." in service_name:
                domain_part = service_name.split()[0].rstrip(".")
                service_url = f"https://{domain_part}"

            entity = {
                "type": "service",
                "value": service_name.lower(),
                "confidence": confidence,
                "sources": [f"holehe:{target}"],
                "source": "tool_output",
                "metadata": {
                    "registered": registered,
                    "email_target": target,
                    "url": service_url,
                },
            }
            entities.append(entity)
            if service_url:
                urls_found.append(service_url)

    # Extract username hints from URLs in output
    extra_urls = extract_urls(raw_stdout)
    all_urls = list(set(urls_found + extra_urls))
    username_hints = extract_usernames_from_urls(all_urls)

    for hint in username_hints:
        entities.append({
            "type": "service",
            "value": hint["platform"],
            "confidence": 0.9,
            "sources": [f"holehe:{target}"],
            "source": "tool_output",
            "metadata": {
                "registered": True,
                "username_hint": hint["username"],
                "url": f"https://{hint['platform']}.com/{hint['username']}",
            },
        })

    return entities
