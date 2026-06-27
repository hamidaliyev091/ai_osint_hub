"""Parse theHarvester output into structured email/domain/IP entities."""

import re
from hub.cooking import extract_emails, extract_domains, extract_urls


def parse(raw_stdout: str, target: str = "") -> list[dict]:
    """Parse theHarvester CLI output.

    theHarvester outputs structured sections:
        [*] Emails found: ...
        [*] Hosts found: ...
        [*] IPs found: ...

    Returns list of email, domain, IP, and URL entities.
    """
    entities = []

    # Parse sectioned output
    current_section = None
    for line in raw_stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Detect section headers
        section_m = re.match(r'\[\*\]\s+(Emails|Hosts|IPs|URLs)\s+found', line, re.IGNORECASE)
        if section_m:
            current_section = section_m.group(1).lower()
            continue

        if not current_section:
            continue

        # Skip summary lines
        if line.startswith("[") or line.startswith("Total"):
            continue

        if current_section == "emails":
            entries = _extract_emails_from_line(line, target)
        elif current_section == "hosts":
            entries = _extract_hosts_from_line(line, target)
        elif current_section == "ips":
            entries = _extract_ips_from_line(line, target)
        elif current_section == "urls":
            entries = _extract_urls_from_line(line, target)
        else:
            entries = []

        entities.extend(entries)

    # If no sectioned output found, try broad extraction
    if not entities:
        entities.extend(_broad_extract(raw_stdout, target))

    return entities


def _extract_emails_from_line(line: str, target: str) -> list[dict]:
    """Extract email entities from a line."""
    entities = []
    emails = extract_emails(line)
    for email in emails:
        entities.append({
            "type": "email",
            "value": email.lower(),
            "confidence": 0.85,
            "sources": [f"theHarvester:{target}"],
            "source": "tool_output",
            "metadata": {"source_tool": "theHarvester", "target": target},
        })
    return entities


def _extract_hosts_from_line(line: str, target: str) -> list[dict]:
    """Extract host/domain entities from a line."""
    entities = []
    # theHarvester host lines: "hostname:ip" or just "hostname"
    for part in line.split():
        part = part.strip().rstrip(".")
        if ":" in part:
            host, ip = part.rsplit(":", 1)
            host = host.strip()
            if _looks_like_domain(host):
                entities.append({
                    "type": "domain",
                    "value": host.lower(),
                    "confidence": 0.80,
                    "sources": [f"theHarvester:{target}"],
                    "source": "tool_output",
                    "metadata": {"resolved_ip": ip},
                })
            if _looks_like_ip(ip):
                entities.append({
                    "type": "ip",
                    "value": ip.strip(),
                    "confidence": 0.75,
                    "sources": [f"theHarvester:{target}"],
                    "source": "tool_output",
                    "metadata": {"hostname": host},
                })
        elif _looks_like_domain(part):
            entities.append({
                "type": "domain",
                "value": part.lower(),
                "confidence": 0.80,
                "sources": [f"theHarvester:{target}"],
                "source": "tool_output",
            })
    return entities


def _extract_ips_from_line(line: str, target: str) -> list[dict]:
    """Extract IP entities from a line."""
    entities = []
    for word in line.split():
        word = word.strip()
        if _looks_like_ip(word):
            entities.append({
                "type": "ip",
                "value": word,
                "confidence": 0.75,
                "sources": [f"theHarvester:{target}"],
                "source": "tool_output",
            })
    return entities


def _extract_urls_from_line(line: str, target: str) -> list[dict]:
    """Extract URL entities from a line."""
    entities = []
    urls = extract_urls(line)
    for url in urls:
        # Extract domain from URL
        domain_m = re.search(r'https?://([^/]+)', url)
        domain = domain_m.group(1) if domain_m else url

        entities.append({
            "type": "url",
            "value": url,
            "confidence": 0.80,
            "sources": [f"theHarvester:{target}"],
            "source": "tool_output",
            "metadata": {"domain": domain},
        })
    return entities


def _broad_extract(raw_stdout: str, target: str) -> list[dict]:
    """Broad extraction when no sectioned output is found."""
    entities = []

    for email in extract_emails(raw_stdout):
        entities.append({
            "type": "email", "value": email.lower(), "confidence": 0.75,
            "sources": [f"theHarvester:{target}"], "source": "tool_output",
        })

    for domain in extract_domains(raw_stdout):
        entities.append({
            "type": "domain", "value": domain.lower(), "confidence": 0.70,
            "sources": [f"theHarvester:{target}"], "source": "tool_output",
        })

    return entities


def _looks_like_domain(s: str) -> bool:
    """Check if string looks like a domain name."""
    return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', s))


def _looks_like_ip(s: str) -> bool:
    """Check if string looks like an IPv4 address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
