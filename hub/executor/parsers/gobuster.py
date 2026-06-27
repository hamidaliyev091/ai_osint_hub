"""Parse gobuster output → URL entities (stub — binary not yet integrated).

Returns list[dict] with keys: type, value, confidence, sources, metadata.
"""
import re


def parse(raw_output: str, target: str = "") -> list[dict]:
    """Parse gobuster directory busting output into URL entities.

    V2 stub: gobuster outputs found paths one per line with status codes.
    Returns empty list until integrated.
    """
    entities = []

    # Gobuster output pattern: "/path          (Status: 200) [Size: 1234]"
    path_pattern = re.compile(r'(/\S+)\s+\(Status:\s*(\d+)\)')

    # Also handle simple output: "http://target/path"
    for m in path_pattern.finditer(raw_output):
        path = m.group(1).strip()
        status_code = int(m.group(2))

        if 200 <= status_code < 400:  # Only interesting status codes
            entities.append({
                "type": "url",
                "value": f"{target.rstrip('/')}{path}",
                "confidence": 0.85 if status_code == 200 else 0.60,
                "sources": [f"gobuster:{target}"],
                "source": "tool_output",
                "metadata": {
                    "status_code": status_code,
                    "path": path,
                    "base_url": target,
                },
            })

    return entities
