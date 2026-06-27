"""Parse hashcat output → credential entities.

Supports hashcat --show output format.
Extracts: cracked passwords → credential entities with cracked=True metadata.
"""


def parse(raw_output: str, target: str = "") -> list[dict]:
    """Parse hashcat cracked passwords into credential entities.

    hashcat --show outputs one line per cracked hash: HASH:PASSWORD
    hashcat (cracking mode) outputs: HASH:PASSWORD (one per line to stdout with --stdout)
    Also handles potfile format.
    """
    entities = []

    for line in raw_output.strip().split("\n"):
        line = line.strip()

        # Skip informational lines
        if not line or line.startswith("Session") or line.startswith("Hash") or \
           line.startswith("Dictionary") or line.startswith("Approaching") or \
           line.startswith("Candidates") or line.startswith("Started") or \
           line.startswith("Status") or line.startswith("Time"):
            continue

        # Potfile format: HASH:PLAINTEXT  or  HASH:PLAINTEXT:EXTRA
        # Standard show format: HASH:PLAINTEXT
        if ":" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                # Check if the first part looks like a hash (hex)
                potential_hash = parts[0].strip()
                password = parts[1].strip()

                # Heuristic: if first part is all hex chars, it's likely a hash
                is_hex = all(c in "0123456789abcdefABCDEF" for c in potential_hash)

                if is_hex and len(potential_hash) >= 16:
                    # This is a hash:password pair
                    if password:  # Non-empty password
                        entities.append({
                            "type": "credential",
                            "value": password,
                            "confidence": 0.95,
                            "sources": [f"hashcat:{target}"],
                            "source": "tool_output",
                            "metadata": {
                                "cracked": True,
                                "hash_type": "unknown",
                                "hash_prefix": potential_hash[:16],
                            },
                        })
                elif len(password) >= 1:
                    # Might be non-standard format, but extract anyway
                    entities.append({
                        "type": "credential",
                        "value": password,
                        "confidence": 0.70,
                        "sources": [f"hashcat:{target}"],
                        "source": "tool_output",
                        "metadata": {"cracked": True},
                    })

    return entities
