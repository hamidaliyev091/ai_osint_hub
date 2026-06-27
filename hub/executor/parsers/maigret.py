"""Parse maigret output into structured social profile entities."""

import json


def parse(raw_stdout: str, target_username: str = "") -> list[dict]:
    """Parse maigret JSON output (maigret --json).

    Maigret outputs JSON when --json flag is used:
        {"sitename": {"status": {...}, "url": "...", ...}}

    Returns list of service entities with profile URLs and usernames.
    """
    entities = []

    try:
        data = json.loads(raw_stdout)
    except json.JSONDecodeError:
        # Fallback: maigret might output text with JSON embedded
        # Look for JSON-like blocks
        return _parse_text_fallback(raw_stdout, target_username)

    if not isinstance(data, dict):
        return entities

    for site_name, site_data in data.items():
        if not isinstance(site_data, dict):
            continue

        status = site_data.get("status", {})
        url = site_data.get("url_main", site_data.get("url", ""))
        is_claimed = status.get("is_claimed", status.get("exists", False))
        username_found = status.get("username", target_username)

        entities.append({
            "type": "service",
            "value": site_name.lower(),
            "confidence": 0.95 if is_claimed else 0.60,
            "sources": [f"maigret:{target_username}"],
            "source": "tool_output",
            "metadata": {
                "registered": bool(is_claimed),
                "url": url if url else f"https://{site_name}",
                "username_found": username_found,
                "profile_url": url,
            },
        })

    return entities


def _parse_text_fallback(raw_stdout: str, target_username: str) -> list[dict]:
    """Fallback parser for non-JSON maigret output."""
    entities = []
    import re

    for line in raw_stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("*"):
            continue

        # Lines often look like: "site_name: found" or "site_name: not found"
        m = re.match(r'^([a-zA-Z0-9._-]+):\s+(.+)$', line)
        if m:
            site = m.group(1).strip().lower()
            status_text = m.group(2).strip().lower()
            registered = "found" in status_text or "claimed" in status_text

            entities.append({
                "type": "service",
                "value": site,
                "confidence": 0.90 if registered else 0.55,
                "sources": [f"maigret:{target_username}"],
                "source": "tool_output",
                "metadata": {
                    "registered": registered,
                    "username_found": target_username,
                },
            })

    return entities
