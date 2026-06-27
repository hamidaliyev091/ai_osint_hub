"""Parse ghunt output → Google profile entities."""
import json


def parse(raw_output: str, target: str = "") -> list[dict]:
    """Parse ghunt email lookup output.
    Extracts: Google account services (YouTube, Maps, Photos) and profile data.
    """
    entities = []
    # ghunt outputs JSON when run with --json flag
    if raw_output.strip().startswith("{"):
        try:
            data = json.loads(raw_output)
            # Extract Google services linked to the email
            for svc in data.get("services", []):
                entities.append({
                    "type": "service", "value": svc.get("name", "google_service"),
                    "confidence": 0.90,
                    "sources": [f"ghunt:{target}"], "source": "tool_output",
                    "metadata": svc,
                })
            # Extract profile data
            profile = data.get("profile", {})
            if profile.get("displayName"):
                entities.append({
                    "type": "person", "value": profile["displayName"],
                    "confidence": 0.85,
                    "sources": [f"ghunt:{target}"], "source": "tool_output",
                    "metadata": {"google_id": profile.get("id", "")},
                })
            if profile.get("youtubeChannel"):
                entities.append({
                    "type": "service", "value": profile["youtubeChannel"],
                    "confidence": 0.85,
                    "sources": [f"ghunt:{target}"], "source": "tool_output",
                    "metadata": {"platform": "youtube"},
                })
        except json.JSONDecodeError:
            pass
    return entities
