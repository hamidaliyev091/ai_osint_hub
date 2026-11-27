# Contributing to AI OSINT Hub

Thank you for helping improve AI OSINT Hub! Please follow these guidelines so the deterministic core, cross-platform toolchain, and security boundaries remain intact.

## Development Setup

Python **3.10+** is required (CI tests Python 3.11 and 3.13 across Linux, Windows, and macOS).

### Linux / macOS

```bash
git clone https://github.com/hamidaliyev091/ai_osint_hub.git
cd ai_osint_hub
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### Windows (PowerShell 5.1)

```powershell
git clone https://github.com/hamidaliyev091/ai_osint_hub.git
cd ai_osint_hub
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

> **Tip:** You can also use `uv` (`uv venv && uv pip install -e ".[dev]"`) or launch the Web Workbench directly with `./scripts/launch.sh` (POSIX) or `.\scripts\launch.ps1` (Windows).

---

## Running Tests & Verification

The default pytest suite is **100% deterministic and offline** (live-network tests are gated behind `AI_OSINT_HUB_LIVE=1`):

```bash
# Full offline suite
python -m pytest -q --tb=short

# Focused module tests
python -m pytest tests/test_security.py tests/test_erkg.py -q
python -m pytest tests/test_v2_release.py -q

# Verify CLI & 32-tool capability matrix
python -m hub.cli tools
python -m hub.cli doctor --no-smoke
```

Opt-in live smoke tests (requires internet access; targets RFC-2606 / public test endpoints):

```bash
AI_OSINT_HUB_LIVE=1 python -m pytest tests/test_live_smoke.py -q
```

---

## Architecture & Module Map

- `hub/models.py` — single source of truth for Pydantic domain models and closed enums (`EpistemicStatus`, `EntityType`, `EdgeType`).
- `hub/erkg/` — entity resolution, deterministic confidence math, SQLite/WAL transactional store, graph view, analytics, and ingestion.
- `hub/tools/` — capability registry (`capabilities.py`), cross-platform binary locator (`locator.py`), hardened async subprocess runtime (`runtime.py`), deterministic parsers (`parsers/`), and native passive collectors (`builtin/`).
- `hub/security/` — pre-spawn scope/SSRF policy (`policy.py`), indirect prompt-injection & visual quarantine (`quarantine.py`), and secret redaction (`redaction.py`).
- `hub/investigation/` — hypothesis generation, mathematical pivot scoring, stopping rules, quarantined reflection, and investigation engine loop.
- `hub/ai/` — optional hybrid local/cloud AI & VLM layer (`enabled=False` default).
- `hub/bundle.py` & `hub/demo.py` — hardened `.osintcase.zip` export/import and synthetic offline demo case.
- `hub/service.py`, `hub/cli.py`, `hub/mcp_server.py`, `hub/web.py`, `hub/reporting.py` — parity service (`overview`, `visuals`, `upload_visual`, etc.), CLI, stdio MCP + MCP App, 4-theme Workbench, and evidence-cited dossiers.

---

## Pull Request Security Invariants Checklist

Before submitting any PR, verify every item below:

- [ ] **Closed Epistemic Status:** No statuses added outside `EpistemicStatus` (`CONFIRMED`, `CORROBORATED`, `SINGLE_SOURCE_LEAD`, `HYPOTHESIS`, `CONTRADICTED`, `COLLECTION_FAILURE`). Confidence values come from `hub.erkg.confidence.assess`.
- [ ] **Evidence Backing:** Every non-hypothesis claim cites at least one immutable `EvidenceArtifact` inside an atomic SQLite transaction.
- [ ] **No Fake Tool Runs:** Missing binaries are reported as `MISSING`, never mocked in `hub/`. Tests inject mocks via `tests/mock_tools.py`.
- [ ] **Subprocess Safety:** All subprocesses run through `hub/tools/runtime.py` or `hub/tools/locator.py` with `shell=False`, `stdin=subprocess.DEVNULL`, and explicit `argv` lists. No top-level POSIX-only imports (e.g., `fcntl`).
- [ ] **Scope & SSRF Gates:** `hub/security/policy.py` (`check_capability`, `assert_safe_host`) gates every spawn and network collector. `allow_active_recon=False` by default; `INTRUSIVE_BLOCKED` tools never spawn.
- [ ] **Zero-LLM & Non-Promotion:** `AIConfig.enabled` remains `False` by default; AI/VLM outputs carry `PROVENANCE_AI_INFERRED`/`PROVENANCE_VLM_EXTRACTED` (`direct=False`) and never auto-promote to `CONFIRMED`.
- [ ] **Prompt & Visual Quarantine:** All external text and visual/OCR/EXIF metadata sent to LLMs/VLMs pass through `hub/security/quarantine.py` (`<untrusted_osint_data>` / `<untrusted_visual_data>`).
- [ ] **Secret Hygiene:** No raw API keys, tokens, or credentials in code, tests, logs, or SQLite artifacts. Secrets register with `hub/security/redaction.py`.
- [ ] **DOM & XSS Safety:** Zero `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, or `eval` in `hub/web.py`, `hub/mcp_server.py`, or `hub/reporting.py`. Markdown links allow only `http:`, `https:`, and `mailto:`. Zero `backdrop-filter` or external runtime CDN dependencies.
- [ ] **Bundle Safety:** Any archive handling validates Zip-Slip paths, symlinks, compression-bomb limits, SHA-256 digests, and SQLite `trusted_schema = OFF` + `integrity_check`.
- [ ] **Tests Pass:** Full offline `python -m pytest -q` passes across all tests with zero failures.
