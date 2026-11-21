"""Deterministic data processing — no AI reasoning.

Structured into 4 sections for future split:
  1. Parse      — extract structured data from unstructured text
  2. Normalize  — canonicalize and deduplicate entities
  3. Hypothesis — generate investigative leads from known entities
  4. Confidence — score entity reliability
"""

import re
from typing import Optional


# ═══════════════════════════════════════════════════════════
# SECTION 1: Parse
# ═══════════════════════════════════════════════════════════

# ── NL Input Parsing ──────────────────────────────────

_COMMON_NAMES = {
    "john", "jane", "mohammed", "fatima", "ali", "sarah",
    "ahmed", "maria", "omar", "layla", "hassan", "zainab", "yusuf", "noor",
    "emir", "zara", "orxan", "aysel", "elnur", "gunel", "turan", "sevda",
    "ruslan", "aygun", "vugar", "leyla",  # Turkic/Azeri names (diverse set)
}

_INTEREST_KEYWORDS = [
    "likes", "plays", "enjoys", "hobby", "interests", "into", "fan of",
    "drives", "owns", "works at", "studies",
]

_SUFFIX_PATTERN = re.compile(r'\b(\d{2,4})\b')

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
_DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
_URL_RE = re.compile(r'https?://[^\s<>"]+')
_PHONE_CANDIDATE_RE = re.compile(r'(?<![\w])\+?\d[\d\s().-]{6,}\d(?![\w])')


def extract_phones(text: str) -> list[str]:
    """Extract plausible phone numbers (E.164-ish) from arbitrary text.

    Requires either an explicit ``+`` prefix with 8-15 digits or a bare number
    with 10-15 digits, which avoids matching years, IDs and timestamps.
    """
    results: set[str] = set()
    for match in _PHONE_CANDIDATE_RE.finditer(text or ""):
        raw = match.group(0).strip()
        digits = re.sub(r"\D", "", raw)
        has_plus = raw.startswith("+")
        if not ((has_plus and 8 <= len(digits) <= 15)
                or (not has_plus and 10 <= len(digits) <= 15)):
            continue
        # Reject obvious dates (yyyy-mm-dd / dd-mm-yyyy) rather than phone-like
        # groupings such as "(415) 555-2671".
        if (re.fullmatch(r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}", raw)
                or re.fullmatch(r"\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}", raw)):
            continue
        results.add(("+" if has_plus else "") + digits)
    return sorted(results)


def parse_raw_input(text: str) -> dict:
    """Extract structured entities from messy NL.

    Returns {persons, interests, numeric_suffixes, associations, emails, domains}
    """
    text_lower = text.lower()
    words = set(text_lower.replace(",", " ").replace(".", " ").split())

    # Persons: known names found in text
    persons = []
    for name in _COMMON_NAMES:
        if name in words or name in text_lower:
            # Avoid duplicates from word boundaries
            if not any(p["name"] == name for p in persons):
                persons.append({"name": name.capitalize(), "confidence": 0.8})

    # Numeric suffixes
    suffixes = list(set(_SUFFIX_PATTERN.findall(text)))

    # Interests (simple keyword extraction)
    interests = []
    for kw in _INTEREST_KEYWORDS:
        idx = text_lower.find(kw)
        if idx >= 0:
            # Grab the next word or short phrase after the keyword
            after = text[idx + len(kw):].strip().split(",")[0].split(".")[0]
            after = after.strip().split()[0] if after.split() else ""
            word = after.rstrip(".,;!?")
            if word and len(word) > 1 and word not in _COMMON_NAMES:
                interests.append(word)

    # Associations (sister, brother, friend, colleague, etc.)
    associations = []
    rel_patterns = [
        (r'(?:sister|brother|mother|father|friend|colleague|cousin|wife|husband)\s+(?:name\s+is\s+|is\s+|:\s*)?(\w+)', "relation_mention"),
        (r'(\w+)\s+is\s+(?:my\s+)?(?:sister|brother|mother|father)', "name_is_relation"),
    ]
    seen_assoc = set()
    for pattern, _ in rel_patterns:
        for m in re.finditer(pattern, text_lower):
            name = m.group(1).strip()
            if name in _COMMON_NAMES and name not in seen_assoc:
                seen_assoc.add(name)
                # Try to find the relationship word
                rel_match = re.search(r'(sister|brother|mother|father|friend|colleague|cousin|wife|husband)',
                                     text_lower)
                rel = rel_match.group(1) if rel_match else "associate"
                associations.append({"name": name.capitalize(), "relation": rel, "confidence": 0.7})

    # Direct entity extraction from text
    emails = list(set(_EMAIL_RE.findall(text)))
    domains = [d for d in _DOMAIN_RE.findall(text)
               if not d.endswith((".com", ".org", ".net", ".io", ".dev", ".gov", ".edu"))
               or "." in d]  # Keep TLDs, skip noise
    # Only keep domains that look real (have a TLD)
    domains = [d for d in domains if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', d)]

    # Detect bare usernames
    _common_words = {"the", "and", "for", "are", "but", "not", "you", "all", "can",
                     "had", "her", "was", "one", "our", "out", "has", "have", "his",
                     "like", "this", "that", "with", "from", "they", "will", "been",
                     "when", "make", "more", "some", "than", "them", "very", "just",
                     "what", "over", "such", "only", "other", "into", "than", "then",
                     "also", "most", "even", "much", "well", "back", "down", "does",
                     # Relationship terms
                     "sister", "brother", "mother", "father", "friend", "wife",
                     "husband", "cousin", "uncle", "aunt", "son", "daughter",
                     "name", "names", "called", "goes", "nickname", "handle",
                     # Common brands (not usernames)
                     "toyota", "honda", "ford", "bmw", "audi", "tesla", "nissan",
                     "apple", "google", "amazon", "microsoft", "samsung", "sony",
                     # Non-name words that appear in NL input (prevent username extraction)
                     "tibb", "universiteti", "universitet", "studying", "university",
                     "college", "school", "medical", "hospital", "clinic",
                     "years", "year", "old", "lives", "living", "located"}
    # Also exclude common dictionary words 4+ chars (won't be usernames)
    _dictionary_words = {"love", "life", "time", "work", "home", "food", "music",
                         "movie", "book", "game", "sport", "travel", "photo",
                         "video", "story", "world", "people", "happy", "smile",
                         # Age/descriptor words from NL input (bug: "old" from "23 years old")
                         "old", "new", "year", "years", "student", "doctor",
                         "engineer", "teacher", "lawyer", "nurse"}
    _known_tlds = {"com", "org", "net", "io", "dev", "gov", "edu", "mil", "co",
                   "uk", "de", "fr", "jp", "cn", "ru", "br", "au", "ca", "in",
                   "it", "es", "nl", "se", "ch", "pl", "no", "fi", "dk", "be"}
    words_in_text = set(text.lower().replace(",", " ").replace(".", " ").split())
    bare_usernames = []
    for word in words_in_text:
        word = word.strip().lstrip("@")
        if (re.match(r'^[a-zA-Z][a-zA-Z0-9._-]{2,30}$', word)
                and "@" not in word
                and word.lower() not in _COMMON_NAMES
                and word.lower() not in _common_words
                and word.lower() not in _dictionary_words
                and word.lower() not in _known_tlds
                and word not in interests
                and not word.isdigit()):
            bare_usernames.append(word.lower())

    return {
        "persons": persons,
        "interests": interests,
        "numeric_suffixes": suffixes,
        "associations": associations,
        "emails": emails,
        "domains": domains,
        "phones": extract_phones(text),
        "usernames": bare_usernames,
        "raw_text": text,
    }


# ── Entity Extraction from Raw Tool Output ────────────

def extract_emails(text: str) -> list[str]:
    """Extract email addresses from arbitrary text."""
    return list(set(_EMAIL_RE.findall(text)))


def extract_domains(text: str) -> list[str]:
    """Extract domain names from arbitrary text."""
    return list(set(
        d for d in _DOMAIN_RE.findall(text)
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', d)
        and not d.startswith(("http://", "https://"))
    ))


def extract_urls(text: str) -> list[str]:
    """Extract URLs from arbitrary text."""
    return list(set(_URL_RE.findall(text)))


def extract_usernames_from_urls(urls: list[str]) -> list[dict]:
    """Extract username hints from social media URLs.

    github.com/user123 → {platform: github, username: user123}
    """
    platform_patterns = [
        (r"github\.com/([a-zA-Z0-9_-]+)", "github"),
        (r"twitter\.com/([a-zA-Z0-9_]+)", "twitter"),
        (r"reddit\.com/u(?:ser)?/([a-zA-Z0-9_-]+)", "reddit"),
        (r"linkedin\.com/in/([a-zA-Z0-9_-]+)", "linkedin"),
        (r"instagram\.com/([a-zA-Z0-9_.]+)", "instagram"),
        (r"facebook\.com/([a-zA-Z0-9.]+)", "facebook"),
        (r"youtube\.com/@?([a-zA-Z0-9_-]+)", "youtube"),
        (r"tiktok\.com/@([a-zA-Z0-9_.]+)", "tiktok"),
        (r"chess\.com/member/([a-zA-Z0-9_-]+)", "chess"),
        (r"spotify\.com/user/([a-zA-Z0-9_-]+)", "spotify"),
    ]
    results = []
    for url in urls:
        for pattern, platform in platform_patterns:
            m = re.search(pattern, url, re.IGNORECASE)
            if m:
                results.append({"platform": platform, "username": m.group(1).lower()})
    return results


# ═══════════════════════════════════════════════════════════
# SECTION 2: Normalize
# ═══════════════════════════════════════════════════════════

def normalize_entity(entity: dict) -> dict:
    """Canonicalize entity values.

    - lowercase emails
    - strip www. from domains
    - remove trailing slash from URLs
    - strip @ from usernames
    """
    e = dict(entity)
    value = e.get("value", "")

    if e.get("type") == "email":
        e["value"] = value.lower().strip()
    elif e.get("type") == "domain":
        val = value.lower().strip()
        val = re.sub(r'^www\.', '', val)
        val = val.rstrip("/")
        e["value"] = val
    elif e.get("type") == "username":
        e["value"] = value.lstrip("@").lower().strip()
    elif e.get("type") == "url":
        e["value"] = value.rstrip("/")
    elif e.get("type") == "ip":
        e["value"] = value.strip()

    return e


def deduplicate(entities: list[dict]) -> list[dict]:
    """Deduplicate entities by type+value hash.

    When duplicates found, keep highest confidence, merge sources.
    """
    seen: dict[str, dict] = {}
    for entity in entities:
        e = normalize_entity(entity)
        key = f"{e.get('type','')}:{e.get('value','')}".lower()
        if key in seen:
            existing = seen[key]
            existing["confidence"] = max(existing.get("confidence", 0), e.get("confidence", 0))
            existing_sources = existing.get("sources", [])
            for s in e.get("sources", []):
                if s not in existing_sources:
                    existing_sources.append(s)
            existing["sources"] = existing_sources
            if e.get("metadata"):
                # P1-12: Use origin-preserving merge (higher-priority origin wins).
                # raw_input(3) > tool(2) > hypothesis_expansion(1).
                _ORIGIN_PRIORITY = {"raw_input": 3, "tool": 2, "hypothesis_expansion": 1}
                existing_meta = existing.setdefault("metadata", {})
                incoming_meta = e.get("metadata", {})
                existing_origin = existing_meta.get("origin", "")
                incoming_origin = incoming_meta.get("origin", "")
                if existing_origin and incoming_origin:
                    existing_prio = _ORIGIN_PRIORITY.get(existing_origin, 0)
                    incoming_prio = _ORIGIN_PRIORITY.get(incoming_origin, 0)
                    if incoming_prio > existing_prio:
                        existing_meta.update(incoming_meta)
                    else:
                        safe = {k: v for k, v in incoming_meta.items() if k != "origin"}
                        existing_meta.update(safe)
                else:
                    existing_meta.update(incoming_meta)
        else:
            seen[key] = e
    return list(seen.values())


# ═══════════════════════════════════════════════════════════
# SECTION 3: Hypothesis
# ═══════════════════════════════════════════════════════════

# Permutation rules: each is (name, function)
# Functions take: first_name, last_name_or_none, suffix_or_none
_USERNAME_RULES = [
    ("bare_first",       lambda f, l, s: f),
    ("first_suffix",     lambda f, l, s: f"{f}{s}" if s else None),
    ("first_underscore_suffix", lambda f, l, s: f"{f}_{s}" if s else None),
    ("first_dot_suffix", lambda f, l, s: f"{f}.{s}" if s else None),
    ("first_dash_suffix", lambda f, l, s: f"{f}-{s}" if s else None),
    ("suffix_first",     lambda f, l, s: f"{s}{f}" if s else None),
    ("first_last",       lambda f, l, s: f"{f}{l}" if l else None),
    ("first_dot_last",   lambda f, l, s: f"{f}.{l}" if l else None),
    ("first_underscore_last", lambda f, l, s: f"{f}_{l}" if l else None),
    ("flast",            lambda f, l, s: f"{f[0]}{l}" if l and len(f) > 0 else None),
    ("firstl",           lambda f, l, s: f"{f}{l[0]}" if l and len(l) > 0 else None),
    ("f_dot_last",       lambda f, l, s: f"{f[0]}.{l}" if l and len(f) > 0 and len(l) > 0 else None),
    ("last_first",       lambda f, l, s: f"{l}{f}" if l else None),
    ("first_last_suffix", lambda f, l, s: f"{f}{l}{s}" if l and s else None),
    ("flast_suffix",     lambda f, l, s: f"{f[0]}{l}{s}" if l and s and len(f) > 0 else None),
]

_COMMON_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me",
                         "protonmail.com", "icloud.com", "mail.com", "aol.com", "yandex.com"]


def generate_usernames(persons: list[dict], suffixes: list[str],
                       interests: list[str]) -> list[str]:
    """Generate username candidates from person names + suffixes + interests."""
    usernames = set()

    for person in persons:
        name = person.get("name", "").lower()
        # Split into first/last if possible
        parts = name.split()
        first = parts[0] if parts else name
        last = parts[1] if len(parts) > 1 else None

        for suffix in (suffixes if suffixes else [None]):
            for _, rule_fn in _USERNAME_RULES:
                try:
                    result = rule_fn(first, last, suffix)
                    if result and len(result) >= 2:
                        usernames.add(result.lower())
                except (IndexError, TypeError):
                    continue

    # Interest-based usernames
    for interest in interests:
        for person in persons:
            first = person.get("name", "").lower().split()[0]
            usernames.add(f"{first}_{interest}")
            usernames.add(f"{interest}_{first}")
            for suffix in suffixes:
                usernames.add(f"{first}_{interest}{suffix}")

    # Bare names (no suffix, no last)
    for person in persons:
        first = person.get("name", "").lower().split()[0]
        usernames.add(first)

    return sorted(usernames, key=lambda u: len(u))  # Shorter first


def infer_emails(usernames: list[str], domains: list[str] = None) -> list[str]:
    """Infer email addresses from usernames + common providers.

    If domains provided, use those too.
    """
    if domains is None:
        domains = []
    all_domains = list(domains) + _COMMON_EMAIL_DOMAINS

    emails = set()
    for username in usernames:
        # Only infer for plausible usernames (no spaces, no special chars beyond ._-)
        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            continue
        for domain in all_domains:
            emails.add(f"{username}@{domain}")
    # Sort with priority domains first (gmail > outlook > proton > rest alpha).
    # This ensures _group_similar picks the most useful email when all confidences equal.
    _PRIORITY_DOMAINS = {"gmail.com": 0, "outlook.com": 1, "protonmail.com": 2, "proton.me": 3,
                         "icloud.com": 4, "hotmail.com": 5, "yahoo.com": 6, "mail.com": 7,
                         "aol.com": 8, "yandex.com": 9}
    def _domain_rank(email: str) -> tuple:
        domain = email.split("@")[1] if "@" in email else ""
        return (_PRIORITY_DOMAINS.get(domain, 99), email)
    return sorted(emails, key=_domain_rank)


def can_expand(entity: dict) -> bool:
    """Check if an entity is allowed to generate further hypotheses.

    Allowlist-based (P1-14): only raw_input and tool origins can expand.
    Fails closed — entities with unknown or missing origin are denied.
    This prevents recursive hypothesis chains from entities generated
    by previous expansions.
    """
    ALLOWED_ORIGINS = {"raw_input", "tool"}
    origin = entity.get("metadata", {}).get("origin", "")
    # backward compat: empty origin defaults to denied (fails closed)
    return origin in ALLOWED_ORIGINS


# Configurable suffix variants for username expansion (P2-7)
_USERNAME_EXPANSION_SUFFIXES = ["1", "123", "007", "091", "99", "0", "official", "real"]


def expand_hypotheses(new_entities: list[dict], existing_graph=None) -> list[dict]:
    """Generate new investigation candidates from newly found entities.

    Given a set of newly discovered entities, generate new leads:
    - Found a username → infer possible emails
    - Found an email → extract username prefix, generate variants
    - Found URLs with usernames → add those usernames
    """
    hypotheses = []
    seen = set()

    for entity in new_entities:
        etype = entity.get("type", "")
        evalue = entity.get("value", "")

        # Origin-based guard: hypothesis-expanded entities may NEVER
        # generate further hypotheses. Guarantees max expansion depth = 1.
        if not can_expand(entity):
            continue

        if etype == "email" and "@" in evalue:
            prefix = evalue.split("@")[0]
            if prefix not in seen and len(prefix) >= 2:
                seen.add(prefix)
                hypotheses.append({
                    "type": "username",
                    "value": prefix,
                    "confidence": 0.4,
                    "source": f"inferred_from_{etype}",
                    "metadata": {"origin": "hypothesis_expansion"},
                })

        elif etype == "username":
            if evalue not in seen:
                seen.add(evalue)
                # Generate variant usernames
                for suffix in _USERNAME_EXPANSION_SUFFIXES:
                    variant = f"{evalue}{suffix}"
                    if variant not in seen:
                        seen.add(variant)
                        hypotheses.append({
                            "type": "username",
                            "value": variant,
                            "confidence": 0.2,
                            "source": f"variant_of_{evalue}",
                            "metadata": {"origin": "hypothesis_expansion"},
                        })

        elif etype == "service" and entity.get("metadata", {}).get("username_hint"):
            uh = entity["metadata"]["username_hint"]
            if uh not in seen:
                seen.add(uh)
                hypotheses.append({
                    "type": "username",
                    "value": uh,
                    "confidence": 0.5,
                    "source": f"username_hint_from_service",
                    "metadata": {"origin": "hypothesis_expansion"},
                })

    return hypotheses


# ═══════════════════════════════════════════════════════════
# SECTION 4: Confidence
# ═══════════════════════════════════════════════════════════

# ── Confidence Constants ──────────────────────────────
# Provenance → confidence mapping. Used by orchestrator when seeding graph.
CONFIDENCE = {
    "parsed_email": 0.85,         # Directly provided email in raw input
    "parsed_domain": 0.80,        # Directly provided domain
    "parsed_username": 0.85,      # Directly provided or detected username
    "person_raw_input": 0.80,     # Person name extracted from NL
    "associate_raw_input": 0.70,  # Associate (sister, friend) from NL
    "generated_username": 0.30,   # Algorithmically generated username
    "generated_email": 0.25,      # Algorithmically inferred email
    "tool_output_default": 0.70,  # Fallback for tool output entities
}


def score_confidence(entity: dict, source_tool: str = "",
                     tool_output_quality: float = 1.0,
                     corroboration_count: int = 0) -> float:
    """Score entity confidence (0.0–1.0).

    Base: source reliability
      - Direct tool output:         0.90
      - Pattern inference:          0.55
      - Generated hypothesis:       0.20
      - Manual input from user:     0.85

    Multipliers:
      - tool_output_quality: 0.0–1.0 (tool-specific reliability)
      - corroboration: +0.08 per additional source (max +0.20 bonus)
    """
    source_type = entity.get("source", "")

    # Base confidence by source type
    if source_type == "tool_output":
        base = 0.90
    elif source_type == "direct_input":
        base = 0.85
    elif source_type == "pattern_inference":
        base = 0.55
    elif source_type.startswith("inferred_from"):
        base = 0.40
    elif source_type.startswith("variant_of"):
        base = 0.20
    elif source_type.startswith("username_hint"):
        base = 0.50
    else:
        base = 0.35

    # Apply quality multiplier
    score = base * max(0.3, tool_output_quality)

    # Corroboration bonus
    bonus = min(0.20, corroboration_count * 0.08)
    score = min(0.99, score + bonus)
    score = max(0.05, score)  # Floor

    return round(score, 2)
