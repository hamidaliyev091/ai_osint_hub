"""Security layer: code-enforced scope policy + prompt-injection quarantine.

Both modules are deterministic. ``policy`` decides whether a capability may run
at all (and which hosts network collectors may touch); ``quarantine`` renders
attacker-controlled output safe before it ever reaches an LLM prompt.
"""

from hub.security.policy import (
    PolicyDecision,
    assert_safe_host,
    check_capability,
    extract_targets,
    host_in_scope,
    is_public_ip,
)
from hub.security.quarantine import (
    SECURITY_SYSTEM_PROMPT,
    detect_injection,
    sanitize_struct,
    sanitize_untrusted,
    wrap_untrusted,
)

__all__ = [
    "PolicyDecision",
    "assert_safe_host",
    "check_capability",
    "extract_targets",
    "host_in_scope",
    "is_public_ip",
    "SECURITY_SYSTEM_PROMPT",
    "detect_injection",
    "sanitize_struct",
    "sanitize_untrusted",
    "wrap_untrusted",
]
