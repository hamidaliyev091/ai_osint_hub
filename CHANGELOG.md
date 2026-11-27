# Changelog

All notable changes to **AI OSINT Hub** are documented in this file.

## [2.0.0] — 2026-11-27

Complete v2 architecture release: Entity-Resolved Knowledge Graph (SQLite/WAL), hypothesis-driven pivot engine, 32-tool hardened runtime, Gruvbox Material Light Cytoscape Workbench, portable `.osintcase.zip` bundles, optional hardware-adaptive hybrid AI & Vision forensics, and universal MCP App support.

### Added

- **Packaging & One-Click Onboarding:**
  - Package data bundling in `pyproject.toml` (`hub/static/vendor/cytoscape.min.js` included in wheels for `pipx` / `uv tool install`), `Pillow>=10.0` runtime dependency, and `ai-osint-hub` console script.
  - Multi-stage non-root `Dockerfile` (`core` and `full` targets, UID `10001`, `/data` volume, `HEALTHCHECK`) and `docker-compose.yml` (`core`, `full`, and `ai` profiles bound to `127.0.0.1:8000` by default).
  - Cross-platform one-click launchers: `scripts/launch.ps1` (Windows PowerShell 5.1) and `scripts/launch.sh` (macOS/Linux bash).
  - Multi-OS GitHub Actions CI (`ubuntu-latest`, `windows-latest`, `macos-latest` × Python `3.11`, `3.13`) plus wheel asset verification and `docker-build` validation.
- **Interactive Demo Case & Portable Case Bundles:**
  - `hub/demo.py` (`seed_demo_case`, `DEMO_TARGET_ID = "case_demo_aurora"`): deterministic offline *"Aurora Meridian Supply-Chain Attribution"* case with 15 entities, 23 claims (3-tool corroborated `CONFIRMED`, `SINGLE_SOURCE_LEAD`, `CONTRADICTED` timezone conflict, `AI_INFERRED` advisory synthesis), synthetic PNG/EXIF/pHash forensics, timeline, and hypotheses.
  - `hub/bundle.py`: WAL-safe SQLite `.backup()` export and hardened `.osintcase.zip` import (`BUNDLE_FORMAT_VERSION = "2.0.0"`) with optional `redact_pii=True` scrubbing, Zip-Slip/symlink/compression-bomb defenses, SHA-256 verification, and `PRAGMA trusted_schema = OFF` + `PRAGMA integrity_check`.
- **Human-First CLI & Service Parity:**
  - New CLI commands: `web` (auto free-port fallback + `--open` browser launch), `demo`, `export`, `import`, `mcp-config` (`antigravity`, `claude`, `cursor`, `vscode`), and `doctor --no-smoke`.
  - Optional positional `raw_input` on `investigate` so structured seed flags (`--domain`, `--username`, `--email`, etc.) work without passing `""`.
- **Gruvbox Material Light Workbench & Editorial Dossiers (`hub/web.py`, `hub/reporting.py`):**
  - Offline Cytoscape.js 3.35.0 + synchronized `<svg id="graph">` 3-pane workbench (`#fbf1c7`/`#f9f5d7`/`#3c3836`/`#af3a03`) with optional dark mode toggle, responsive across `1280x800`–`3440x1440`.
  - First-Run Empty State (*Load Interactive Demo Case*, *Import .osintcase.zip*, *10-Second MCP Setup*, dismissible 4-step checklist), Guided Intake Presets, Scope & Authorization confirmation modal, `Ctrl/Cmd+K` Command Palette, `Rendered | Raw` DOM-built Markdown dossier viewer (`http:`/`https:`/`mailto:` allowlist only), and Print/PDF CSS polish.
  - New REST endpoints: `POST /api/demo`, `GET /api/investigations/{id}/bundle`, `POST /api/bundles/import`, `GET /api/mcp-config`, `GET /api/investigations/{id}/analytics`, `GET /api/investigations/{id}/timeline`, `GET /api/investigations/{id}/diff/{other_id}`, `POST /api/investigations/{id}/step-batch`, `GET|POST /api/ai/*`, `POST /api/investigations/{id}/reflect`, `POST /api/media/analyze`.
- **Optional Hybrid AI, Vision Forensics & Graph Analytics (`hub/ai/`, `hub/erkg/analytics.py`):**
  - Zero-LLM default (`enabled=False`, `preset=disabled`) with hardware presets (`disabled`, `cpu_light`, `vram_8gb`, `vram_16gb_plus`, `cloud_byok`), `num_ctx`/`keep_alive` Ollama tuning, and copyable `ollama pull` commands.
  - Pure-Python degree & Brandes betweenness centrality, communities, Tarjan bridges, `shortest_path`, perceptual-hash clustering, `build_timeline`, and `diff_investigations`.
- **32-Tool Capability Matrix & Cross-Platform Locator:**
  - Added passive collectors `crtsh_lookup`, `asn_bgp_lookup`, `favicon_hash`, and `media_forensics` (32 total capabilities).
  - Windows `0xC0000142` (`STATUS_DLL_INIT_FAILED`) managed-venv trampoline fallback (`theHarvester`), Windows `nmap` 2.0s probe WSL2 fallback, macOS/Linux extra host PATH search, and per-OS `install_hint()` in `doctor`.
- **Universal MCP App Handshake (`hub/mcp_server.py`):**
  - Stdio MCP server exposing 12 tools + `ui://ai-osint-hub/workbench.html` MCP App resource with `_meta.ui.visibility = ["model", "app"]` and `content[0].text` JSON fallback parsing.

### Security

- Zero-shell `create_subprocess_exec` (`shell=False`, `stdin=DEVNULL`), minimal environment scrubbing, and process-tree timeout termination.
- Pre-spawn code-enforced scope & SSRF guard (`assert_safe_host`, `fetch_safe` manual redirect re-validation), `allow_active_recon=False` default, and `INTRUSIVE_BLOCKED` on `hydra`.
- `<untrusted_osint_data>` and `<untrusted_visual_data>` prompt-injection quarantine, `PROVENANCE_AI_INFERRED` non-promotion, secret redaction registry, and zero-`innerHTML` UI rendering.

---

## Prior Milestone Summary (v2 Rebuild Phases 1–18)

- **Phases 1–5:** Replaced v1 JSON-file orchestrator (`hub/orchestrate.py` kept as cross-platform compatibility shim) with SQLite/WAL ERKG (`hub/erkg/store.py`), deterministic confidence math, hypothesis-driven pivot scoring, hardened `ToolRuntime`, evidence-cited dossiers, and stdio MCP server.
- **Phase 6 (Toolchain Provisioning):** Added `hub/tools/locator.py` and `hub/toolchain/{doctor,provision}.py` with managed venvs, `~/.ai_osint_hub/bin`, and shell-free WSL2 bridging.
- **Phases 7–9:** Added 7 Python-native passive collectors (`photon_crawler`, `github_osint`, `gravatar_lookup`, `pgp_keyserver`, `rdap_lookup`, `wayback_cdx`, `darkweb_ahmia`), unstructured multi-clue intake (`hub/intake.py`), FastAPI Web Workbench (`hub/web.py`), and HTML dossiers (`hub/reporting.py`).
- **Phase 10:** Added 5-provider credential vault (`hub/credentials.py`), secret redaction (`hub/security/redaction.py`), and 4 API collectors (`virustotal_lookup`, `shodan_lookup`, `censys_lookup`, `hunter_lookup`).
- **Phases 11–17:** Hardened `holehe`/`maigret`/`theHarvester`/`sherlock`/`github_osint`/`darkweb_ahmia` signal precision, seed-first round-robin pivoting, 24h provider cooldowns, multi-part public suffix rules, hierarchical `LOCATED_IN`, AZ E.164 normalization, and global `USERNAME` validation.
- **Phase 18:** Introduced `hub/ai/`, `media_forensics`, `crtsh_lookup`, `asn_bgp_lookup`, `favicon_hash`, `hub/erkg/analytics.py`, Gruvbox Material Light Cytoscape Workbench, and Antigravity MCP App UI.
