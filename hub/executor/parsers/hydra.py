"""Parse hydra output → credential entities (stub — binary not yet integrated).

Returns list[dict] with keys: type, value, confidence, sources, metadata.
"""
import re


def parse(raw_output: str, target: str = "") -> list[dict]:
    """Parse hydra brute-force output into credential entities.

    V2 stub: hydra outputs "[port][service] host: ... login: X password: Y".
    Returns empty list until integrated.
    """
    entities = []

    # Hydra success pattern: "[22][ssh] host: 192.168.1.1   login: admin   password: secret"
    cred_pattern = re.compile(
        r'\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.+)'
    )
    for m in cred_pattern.finditer(raw_output):
        port = m.group(1)
        service = m.group(2)
        host = m.group(3)
        login = m.group(4)
        password = m.group(5).strip()

        entities.append({
            "type": "credential",
            "value": f"{login}:{password}",
            "confidence": 0.95,
            "sources": [f"hydra:{target}"],
            "source": "tool_output",
            "metadata": {
                "username": login,
                "password": password,
                "host": host,
                "port": int(port),
                "service": service,
            },
        })

    return entities
