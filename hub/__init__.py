"""AI OSINT Hub v2 — autonomous, evidence-cited OSINT investigation engine.

Architecture:
  * ``hub.erkg``          — Entity-Resolved Knowledge Graph (SQLite/WAL, provenance,
                            claims, epistemic statuses, execution ledger).
  * ``hub.tools``         — Pydantic capability manifests, deterministic parsers,
                            hardened async subprocess runtime.
  * ``hub.security``      — scope gate + indirect prompt-injection quarantine.
  * ``hub.investigation`` — hypotheses, pivot scoring, autonomous loop, reflection.
  * ``hub.service`` / ``hub.cli`` / ``hub.mcp_server`` — transport parity.
"""

__version__ = "2.0.0"
__all__ = ["__version__"]
