"""Tool metadata registry — validation, resolution, discovery.

Plain dataclasses and lookup dicts. No abstractions.
The registry is the single source of truth for what tools exist,
what entities they handle, and how to invoke them.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ToolMeta:
    """Metadata for one tool in the registry."""
    name: str
    display_name: str
    description: str
    entity_input: list[str]          # Entity types this tool accepts
    entity_output: list[str]         # Entity types this tool produces
    params: dict                     # Param name → {type, format, required}
    dangerous: bool = False
    active: bool = False             # True = interacts with target infrastructure
    tool_class: str = ""             # Broad class for scoring (email_service_mapping, etc.)
    default_priority: float = 0.5
    timeout_s: int = 120
    binary: str = ""                 # CLI binary name
    cli_map: dict = field(default_factory=dict)  # Param name → CLI flag (None = positional)
    parser: str = ""                 # Dotted path to parser function
    extra_flags: list[str] = field(default_factory=list)  # Extra CLI flags (P2-2)


# ── Tool class base weights (used by candidate scoring) ──
TOOL_CLASS_WEIGHTS = {
    "email_service_mapping": 0.70,    # holehe
    "breach_lookup":         0.65,    # h8mail
    "username_enumeration":  0.60,    # maigret
    "domain_harvesting":     0.55,    # theHarvester
    "hypothesis_generation": 0.30,    # cooking.expand_hypotheses (virtual action)
    # V2 active tools
    "password_cracking":     0.40,    # hashcat
    "online_brute_force":    0.35,    # hydra
    "network_scanning":      0.55,    # nmap
    "subdomain_enumeration": 0.50,    # amass
    "directory_busting":     0.45,    # gobuster
    # V3 free OSINT tools
    "social_content_scraping": 0.45,   # snscrape
    "phone_intelligence":      0.50,   # phoneinfoga
}


# ── Tool Registry ──────────────────────────────────────────

TOOL_REGISTRY: dict[str, ToolMeta] = {
    "holehe": ToolMeta(
        name="holehe",
        display_name="Holehe Email-to-Service Mapper",
        description="Check if an email is registered on 200+ online services",
        entity_input=["email"],
        entity_output=["service", "username_hint", "profile_url"],
        params={
            "email": {"type": "string", "format": "email", "required": True},
        },
        dangerous=False,
        active=False,
        tool_class="email_service_mapping",
        default_priority=0.9,
        timeout_s=120,
        binary="holehe",
        cli_map={"email": None},  # positional: holehe email@example.com
        parser="hub.executor.parsers.holehe:parse",
        extra_flags=["--no-color"],
    ),
    "maigret": ToolMeta(
        name="maigret",
        display_name="Maigret Username Search",
        description="Search a username across 2500+ social platforms",
        entity_input=["username"],
        entity_output=["service", "profile_url", "username"],
        params={
            "usernames": {"type": "array", "items": {"type": "string"}, "required": True},
        },
        dangerous=False,
        active=False,
        tool_class="username_enumeration",
        default_priority=0.9,
        timeout_s=900,
        binary="maigret",
        cli_map={"usernames": None},  # positional
        parser="hub.executor.parsers.maigret:parse",
    ),
    "h8mail": ToolMeta(
        name="h8mail",
        display_name="h8mail Breach Lookup",
        description="Check email against local public breach indices",
        entity_input=["email"],
        entity_output=["breach", "credential_hash", "exposed_field"],
        params={
            "email": {"type": "string", "format": "email", "required": True},
        },
        dangerous=False,
        active=False,
        tool_class="breach_lookup",
        default_priority=0.85,
        timeout_s=60,
        binary="h8mail",
        cli_map={"email": "-t"},
        parser="hub.executor.parsers.h8mail:parse",
    ),
    "theHarvester": ToolMeta(
        name="theHarvester",
        display_name="theHarvester OSINT Harvester",
        description="Harvest emails, subdomains, IPs from public sources",
        entity_input=["domain", "email"],
        entity_output=["email", "domain", "ip", "url"],
        params={
            "domain": {"type": "string", "format": "hostname", "required": True},
            "email":  {"type": "string", "format": "email", "required": False},
        },
        dangerous=False,
        active=False,
        tool_class="domain_harvesting",
        default_priority=0.8,
        timeout_s=120,
        binary="theHarvester",
        cli_map={"domain": "-d", "email": "-e"},
        parser="hub.executor.parsers.theharvester:parse",
    ),
    # ══════════════════════════════════════════════════════════
    # V2 Active Tools (dangerous=False per user directive)
    # ══════════════════════════════════════════════════════════
    "nmap": ToolMeta(
        name="nmap",
        display_name="Nmap Network Scanner",
        description="Scan IPs and domains for open ports, services, and OS detection",
        entity_input=["ip", "domain"],
        entity_output=["ip", "service", "port"],
        params={
            "target": {"type": "string", "format": "hostname", "required": True},
        },
        dangerous=False,
        active=True,
        tool_class="network_scanning",
        default_priority=0.75,
        timeout_s=300,
        binary="nmap",
        cli_map={"target": None},  # positional
        parser="hub.executor.parsers.nmap:parse",
    ),
    "amass": ToolMeta(
        name="amass",
        display_name="Amass Subdomain Enumerator",
        description="Enumerate subdomains via passive and active DNS reconnaissance",
        entity_input=["domain"],
        entity_output=["domain", "ip"],
        params={
            "domain": {"type": "string", "format": "domain", "required": True},
        },
        dangerous=False,
        active=True,
        tool_class="subdomain_enumeration",
        default_priority=0.70,
        timeout_s=300,
        binary="amass",
        cli_map={"domain": "-d"},
        parser="hub.executor.parsers.amass:parse",
    ),
    "hashcat": ToolMeta(
        name="hashcat",
        display_name="Hashcat Password Cracker",
        description="Offline password hash cracking via wordlist, rule, and mask attacks",
        entity_input=["hash"],
        entity_output=["credential"],
        params={
            "hash": {"type": "string", "format": "filepath", "required": True},
        },
        dangerous=False,
        active=True,
        tool_class="password_cracking",
        default_priority=0.30,
        timeout_s=600,
        binary="hashcat",
        cli_map={"hash": None},  # positional
        parser="hub.executor.parsers.hashcat:parse",
    ),
    "hydra": ToolMeta(
        name="hydra",
        display_name="Hydra Online Brute-Force",
        description="Online brute-force against network services (SSH, FTP, HTTP, etc.)",
        entity_input=["service"],
        entity_output=["credential"],
        params={
            "service": {"type": "string", "required": True},
            "username": {"type": "string", "required": False},
            "password": {"type": "string", "required": False},
        },
        dangerous=False,
        active=True,
        tool_class="online_brute_force",
        default_priority=0.25,
        timeout_s=300,
        binary="hydra",
        cli_map={"service": None, "username": "-l", "password": "-p"},
        parser="hub.executor.parsers.hydra:parse",
    ),
    "gobuster": ToolMeta(
        name="gobuster",
        display_name="Gobuster Directory Buster",
        description="Brute-force directories and files on web servers",
        entity_input=["url"],
        entity_output=["url"],
        params={
            "url": {"type": "string", "format": "url", "required": True},
        },
        dangerous=False,
        active=True,
        tool_class="directory_busting",
        default_priority=0.35,
        timeout_s=300,
        binary="gobuster",
        cli_map={"url": "-u"},
        parser="hub.executor.parsers.gobuster:parse",
    ),
    # ══════════════════════════════════════════════════════════
    # V3 Free OSINT Tools (dangerous=False)
    # ══════════════════════════════════════════════════════════
    "sherlock": ToolMeta(
        name="sherlock",
        display_name="Sherlock Username Search",
        description="Fast username search across ~300 social platforms",
        entity_input=["username"],
        entity_output=["service", "profile_url"],
        params={
            "username": {"type": "string", "required": True},
        },
        dangerous=False,
        active=False,
        tool_class="username_enumeration",
        default_priority=0.85,
        timeout_s=180,
        binary="sherlock",
        cli_map={"username": None},  # positional: sherlock username
        parser="hub.executor.parsers.sherlock:parse",
    ),
    "ghunt": ToolMeta(
        name="ghunt",
        display_name="GHunt Google Account OSINT",
        description="Extract Google account data: YouTube, Maps reviews, Photos from Gmail",
        entity_input=["email"],
        entity_output=["service", "username", "profile_url"],
        params={
            "email": {"type": "string", "format": "email", "required": True},
        },
        dangerous=False,
        active=False,
        tool_class="email_service_mapping",
        default_priority=0.80,
        timeout_s=120,
        binary="ghunt",
        cli_map={"email": None},  # positional after subcommand
        extra_flags=["email"],    # ghunt email test@gmail.com
        parser="hub.executor.parsers.ghunt:parse",
    ),
    "phoneinfoga": ToolMeta(
        name="phoneinfoga",
        display_name="Phoneinfoga Phone Intelligence",
        description="Phone number intelligence: carrier, location, social profiles, VoIP detection",
        entity_input=["phone"],
        entity_output=["service", "person", "location"],
        params={
            "phone": {"type": "string", "format": "phone", "required": True},
        },
        dangerous=False,
        active=False,
        tool_class="phone_intelligence",
        default_priority=0.75,
        timeout_s=120,
        binary="phoneinfoga",
        cli_map={"phone": "-n"},
        extra_flags=["scan"],  # subcommand: phoneinfoga scan -n <number>
        parser="hub.executor.parsers.phoneinfoga:parse",
    ),
    "snscrape": ToolMeta(
        name="snscrape",
        display_name="snscrape Social Media Scraper",
        description="Scrape social media profiles and posts without API keys (Twitter, Instagram, Reddit, Facebook)",
        entity_input=["username"],
        entity_output=["url", "person"],
        params={
            "username": {"type": "string", "required": True},
        },
        dangerous=False,
        active=False,
        tool_class="social_content_scraping",
        default_priority=0.65,
        timeout_s=180,
        binary="snscrape",
        cli_map={"username": None},
        parser="hub.executor.parsers.snscrape:parse",
    ),
    "whatweb": ToolMeta(
        name="whatweb",
        display_name="WhatWeb Technology Fingerprinter",
        description="Identify CMS, frameworks, server software, analytics on websites",
        entity_input=["domain", "url"],
        entity_output=["service", "url"],
        params={
            "target": {"type": "string", "format": "hostname", "required": True},
        },
        dangerous=False,
        active=True,
        tool_class="directory_busting",
        default_priority=0.55,
        timeout_s=120,
        binary="whatweb",
        cli_map={"target": None},  # positional: whatweb example.com
        parser="hub.executor.parsers.whatweb:parse",
    ),
}


# ── Public API ─────────────────────────────────────────────

def get_tool(name: str) -> Optional[ToolMeta]:
    """Get tool metadata by name."""
    return TOOL_REGISTRY.get(name)


def list_tools() -> list[str]:
    """List all registered tool names."""
    return list(TOOL_REGISTRY.keys())


def for_entity(entity_type: str) -> list[str]:
    """Return tool names that accept the given entity type as input."""
    result = []
    for name, meta in TOOL_REGISTRY.items():
        if entity_type in meta.entity_input:
            result.append(name)
    # Sort by default_priority descending
    result.sort(key=lambda n: TOOL_REGISTRY[n].default_priority, reverse=True)
    return result


def is_dangerous(tool_name: str) -> bool:
    """Check if a tool requires authorization before execution."""
    meta = TOOL_REGISTRY.get(tool_name)
    return meta.dangerous if meta else False


def is_active(tool_name: str) -> bool:
    """Check if a tool actively interacts with target infrastructure."""
    meta = TOOL_REGISTRY.get(tool_name)
    return meta.active if meta else False


def get_tool_class(tool_name: str) -> str:
    """Get the tool class for scoring purposes."""
    meta = TOOL_REGISTRY.get(tool_name)
    return meta.tool_class if meta else ""


def get_tool_class_weight(tool_name: str) -> float:
    """Get the base scoring weight for a tool's class."""
    tc = get_tool_class(tool_name)
    return TOOL_CLASS_WEIGHTS.get(tc, 0.3)


def validate(tool_name: str, params: dict) -> tuple[bool, Optional[str]]:
    """Validate params against tool schema.

    Returns (is_valid, error_message).
    """
    meta = TOOL_REGISTRY.get(tool_name)
    if meta is None:
        return False, f"Unknown tool: {tool_name}"

    for pname, pschema in meta.params.items():
        if pschema.get("required", False) and pname not in params:
            return False, f"Missing required param '{pname}' for {tool_name}"
        if pname in params:
            ptype = pschema.get("type", "string")
            if ptype == "email" and not isinstance(params[pname], str):
                return False, f"Param '{pname}' must be a string email"
            if ptype == "array" and not isinstance(params[pname], list):
                return False, f"Param '{pname}' must be an array"

    return True, None


def resolve(tool_name: str) -> Optional[dict]:
    """Resolve tool metadata needed for execution.

    Returns {binary, cli_map, parser} or None if unknown.
    """
    meta = TOOL_REGISTRY.get(tool_name)
    if meta is None:
        return None
    return {
        "binary": meta.binary,
        "cli_map": meta.cli_map,
        "parser": meta.parser,
        "timeout_s": meta.timeout_s,
        "dangerous": meta.dangerous,
    }


def export_catalog() -> str:
    """Generate markdown tool catalog from registry."""
    lines = [
        "# Tool Catalog",
        "",
        "| Tool | Entity Input | Entity Output | Dangerous | Active | Priority | Timeout |",
        "|------|-------------|---------------|-----------|--------|----------|---------|",
    ]
    for name, meta in sorted(TOOL_REGISTRY.items()):
        lines.append(
            f"| {name} | {', '.join(meta.entity_input)} | "
            f"{', '.join(meta.entity_output)} | "
            f"{'⚠ Yes' if meta.dangerous else 'No'} | "
            f"{'Yes' if meta.active else 'No'} | "
            f"{meta.default_priority} | {meta.timeout_s}s |"
        )
    return "\n".join(lines)
