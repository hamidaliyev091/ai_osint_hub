"""Parse amass output → entities.

Supports amass JSON output (-json flag).
Extracts: subdomains → domain entities, resolved addresses → IP entities.
"""
import json


def parse(raw_output: str, target: str = "") -> list[dict]:
    """Parse amass enum output into domain and IP entities.

    Expects amass output with -json flag: one JSON object per line.
    Format: {"name":"sub.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4"}]}
    """
    entities = []
    seen_domains = set()
    seen_ips = set()

    for line in raw_output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # Skip non-JSON lines (status messages, warnings)
            if line.startswith("{") and line.endswith("}"):
                # Looks like JSON but failed to parse — try to extract what we can
                pass
            continue

        name = record.get("name", "")
        if name and name not in seen_domains:
            seen_domains.add(name)
            entities.append({
                "type": "domain",
                "value": name,
                "confidence": 0.85,
                "sources": [f"amass:{target}"],
                "source": "tool_output",
                "metadata": {
                    "parent_domain": record.get("domain", target),
                    "source": record.get("sources", []),
                },
            })

        for addr in record.get("addresses", []):
            ip = addr.get("ip", "")
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                entities.append({
                    "type": "ip",
                    "value": ip,
                    "confidence": 0.80,
                    "sources": [f"amass:{name or target}"],
                    "source": "tool_output",
                    "metadata": {
                        "hostname": name,
                        "asn": addr.get("asn"),
                        "cidr": addr.get("cidr"),
                    },
                })

    return entities
