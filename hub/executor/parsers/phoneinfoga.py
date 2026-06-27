"""Parse phoneinfoga output → phone intelligence entities."""
import re


def parse(raw_output: str, target: str = "") -> list[dict]:
    """Parse phoneinfoga scan output.
    Extracts: carrier, location, VoIP detection, social profiles linked to phone.
    """
    entities = []
    # Extract carrier info
    carrier_m = re.search(r'Carrier:\s*(.+)', raw_output)
    if carrier_m:
        entities.append({
            "type": "service", "value": carrier_m.group(1).strip(),
            "confidence": 0.85,
            "sources": [f"phoneinfoga:{target}"], "source": "tool_output",
            "metadata": {"phone": target, "type": "carrier"},
        })
    # Extract location
    loc_m = re.search(r'Location:\s*(.+)', raw_output)
    if loc_m:
        entities.append({
            "type": "location", "value": loc_m.group(1).strip(),
            "confidence": 0.70,
            "sources": [f"phoneinfoga:{target}"], "source": "tool_output",
            "metadata": {"phone": target},
        })
    # Extract social profiles found
    for m in re.finditer(r'(\w+)\s*profile:\s*(https?://\S+)', raw_output, re.I):
        entities.append({
            "type": "service", "value": m.group(1),
            "confidence": 0.75,
            "sources": [f"phoneinfoga:{target}"], "source": "tool_output",
            "metadata": {"url": m.group(2), "phone": target},
        })
    return entities
