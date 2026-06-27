"""Parse snscrape output → social media content entities."""
import json


def parse(raw_output: str, target: str = "") -> list[dict]:
    """Parse snscrape JSON output.
    Extracts: tweet/post URLs, user metadata, content statistics.
    """
    entities = []
    seen_urls = set()
    for line in raw_output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            url = record.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                entities.append({
                    "type": "url", "value": url,
                    "confidence": 0.85,
                    "sources": [f"snscrape:{target}"], "source": "tool_output",
                    "metadata": {
                        "date": str(record.get("date", "")),
                        "content": str(record.get("content", ""))[:200],
                        "username": target,
                        "platform": record.get("source", ""),
                    },
                })
            # Extract mentioned users
            user = record.get("user", {}).get("username", "")
            if user:
                entities.append({
                    "type": "username", "value": str(user),
                    "confidence": 0.80,
                    "sources": [f"snscrape:{target}"], "source": "tool_output",
                    "metadata": {"displayname": str(record.get("user", {}).get("displayname", "")),
                                 "platform": "twitter"},
                })
        except (json.JSONDecodeError, KeyError):
            continue
    return entities
