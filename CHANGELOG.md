# Changelog

All notable changes to **AI OSINT Hub** are documented in this file.

## [2.1.0] — 2026-11-27

Recruiter-grade accuracy, visual forensics, simplified AI, and responsive 4-theme Workbench release while preserving the deterministic zero-LLM core, 32-tool runtime, `.osintcase.zip` bundles (`2.0.0` bundle schema compatibility), Docker support, and MCP App handshake.

### Added

- **SSRF-Safe Automatic Photo & Visual Harvesting (`hub/tools/visual_harvester.py`):**
  - Automatically discovers, validates, and caches safe public images from live tool outputs (`avatar_url`, Gravatar `d=404` probes, `og:image` / `twitter:image`, site favicons) into `<case_dir>/media/`.
  - Hardened with `fetch_safe` + `assert_safe_host` SSRF checks on every hop, 5 MB size cap, 8s timeout, Pillow magic/dimension validation, SVG/HTML rejection, sanitized EXIF/GPS extraction, and 64-bit `dHash`/`pHash` correlation.
  - Export/import `.osintcase.zip` bundles (`hub/bundle.py`) preserve validated `media/*` assets under Zip-Slip and extension allowlist rules.
- **Overview & Visuals Workbench (`hub/web.py`, `hub/service.py`, `hub/cli.py`, `hub/mcp_server.py`):**
  - New parity operations and routes: `overview` (`GET /api/investigations/{id}/overview`), `visuals` (`GET /api/investigations/{id}/visuals`), `upload_visual` (`POST /api/investigations/{id}/visuals/upload`), and `GET /api/investigations/{id}/media/{filename}` (`X-Content-Type-Options: nosniff`).
  - **4 Enterprise Themes** with instant top-bar switching (`localStorage` + autofill styling): `clean-light` (default slate/white), `warm-paper`, `midnight-slate`, and `gruvbox-dark`.
  - Decluttered multi-viewport layout (`1280×800` laptops to ultrawide): compact Cases rail, `+ New Investigation` modal, grouped Tools (`Ready` vs. `Policy Blocked` vs. `Needs Key` with Hydra `BLOCKED`), **Overview** default tab, **Visuals & Photos** gallery/match/upload view, spacious `cose` Cytoscape graph with matte label pills, and auto-selected primary subject inspector.
  - Enriched `case_demo_aurora` (`hub/demo.py`) with 3 offline synthetic PNGs (`aurora_github.png`, `aurora_gravatar.png`, `aurora_site_favicon.png`) demonstrating automatic cross-platform pHash avatar matching and EXIF forensics.
- **Simplified 4-Mode AI & Optional `[local-ai]` (`hub/ai/`, `pyproject.toml`):**
  - Optional `pip install "ai-osint-hub[local-ai]"` (`fastembed>=0.4.0` ONNX Runtime) for zero-daemon local text (`BAAI/bge-small-en-v1.5`) and CLIP visual similarity (`Qdrant/clip-ViT-B-32-vision`) with clean offline deterministic fallback.
  - Simplified `AIConfig.mode` (`off` | `local_embedded` | `ollama` | `cloud`) while keeping all legacy `AI_PRESETS_CATALOG` keys intact.

### Fixed

- Removed `EdgeType.HAS_EMAIL` from `FUNCTIONAL_PREDICATES` (`hub/models.py`) so multiple verified emails on a subject never trigger false contradictions; tagged `*@users.noreply.github.com` as synthetic/noreply.
- Fixed `derive_entity_drafts` for `EntityType.EMAIL` (`hub/erkg/resolution.py`) to classify hostnames via `split_hostname` so subdomains like `users.noreply.github.com` never duplicate as root `DOMAIN` entities, and tagged public freemail/noreply infrastructure domains cleanly.
- Added `ERKGStore.merge_entities` and `EvidenceIngestor._unify_duplicate_persons` to merge duplicate `PERSON` entities sharing verified handles or non-role emails.
- Filtered `github_osint` bot committers (`web-flow`, `dependabot[bot]`, `github-actions[bot]`, `renovate[bot]`, `noreply@github.com`) and suppressed duplicate `github_osint` handle runs in `PivotScorer`.
- Rejected generic URL paths (`/members`, `/user`, `/profile`, `/login`, `/about`, root `/`) and mismatched handle segments in `sherlock` and `maigret` parsers.
- Fixed `phoneinfoga` `valid` attribute extraction when structured `Country:` / `Local:` / `E164:` fields exist without literal `Valid: true`.
- Replaced raw JSON dict `Entity coverage` output in `hub/reporting.py` with clean readable counts and badge chips.
- Surfaced `policy_blocked=True` / `ui_status="blocked"` honestly for `INTRUSIVE_BLOCKED` tools (`hydra`) while keeping `doctor` binary inventory at 32/32.

---

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
