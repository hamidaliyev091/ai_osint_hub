"""Parse sherlock output → service entities."""
import re


def parse(raw_output: str, target: str = "") -> list[dict]:
    """Parse sherlock username search output.
    Format: [+] site_name: profile_url
    Returns service entities with confidence based on match type.
    """
    entities = []
    for line in raw_output.split("\n"):
        line = line.strip()
        if not line:
            continue
        # [+] Twitter: https://twitter.com/username
        m = re.match(r'\[([+*!?-])\]\s+(.+?):\s*(https?://\S+)', line)
        if m:
            match_type = m.group(1)
            site_name = m.group(2).strip()
            url = m.group(3).strip()
            confidence = 0.95 if match_type == "+" else 0.60 if match_type == "*" else 0.30
            entities.append({
                "type": "service", "value": site_name,
                "confidence": confidence,
                "sources": [f"sherlock:{target}"], "source": "tool_output",
                "metadata": {"url": url, "match_type": match_type, "username": target},
            })
    return entities
