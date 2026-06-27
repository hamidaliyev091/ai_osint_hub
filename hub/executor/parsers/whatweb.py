"""Parse whatweb output → technology fingerprint entities."""
import re


def parse(raw_output: str, target: str = "") -> list[dict]:
    """Parse whatweb scan output.
    Extracts: CMS, frameworks, server software, JavaScript libraries, analytics.
    Format: http://target [200 OK] Country[US], HTTPServer[nginx], JQuery[1.12]
    """
    entities = []
    # Strip ANSI escape codes (\x1b[...m) that whatweb emits in color mode
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw_output)
    # Strip ANSI bracket codes like [1m, [34m, [0m that sometimes remain
    clean = re.sub(r'\[\d+m', '', clean)

    # Extract Technology[value] patterns: "HTTPServer[cloudflare], IP[1.2.3.4]"
    tech_pattern = re.compile(r'(\w+(?:\s+\w+)*)\[([^\]]+)\]')
    for m in tech_pattern.finditer(clean):
        tech_name = m.group(1).strip()
        tech_value = m.group(2).strip()
        # Skip non-tech noise: HTTP status codes, protocol details
        if tech_name in ("200", "301", "302", "404", "GET", "POST", "HEAD",
                         "http", "https", "RESERVED", "ZZ"):
            continue
        entities.append({
            "type": "service", "value": f"{tech_name}:{tech_value}",
            "confidence": 0.90,
            "sources": [f"whatweb:{target}"], "source": "tool_output",
            "metadata": {"technology": tech_name, "version": tech_value, "target": target},
        })
    return entities
