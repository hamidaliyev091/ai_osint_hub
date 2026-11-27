# AGENTS.md — AI OSINT Hub

Project-level operating notes for coding agents. Read before changing the repo.

## What this project is

Autonomous OSINT investigation engine (v2). Python 3.10+, pydantic v2, SQLite,
`asyncio`. Entry points: `hub.cli`, `hub.mcp_server` (stdio), legacy
`hub.orchestrate` shim. Single source of truth for domain models is
`hub/models.py`; single source of truth for tools is `hub/tools/capabilities.py`.

## Commands

```bash
python -m pytest -q --tb=short                       # full deterministic suite
python -m pytest tests/test_engine.py -q             # one area
python -m hub.cli tools                              # capability health (32 tools)
python -m hub.cli doctor                             # per-tool smoke check (32/32 expected)
python -m hub.cli doctor --provision                 # install missing tools, then re-check
python -m hub.cli investigate "example.com" --max-iterations 3 --report md
python -m hub.cli investigate "Linus Torvalds, goes by torvalds, kernel.org" --report md
python -m hub.cli serve --host 127.0.0.1 --port 8000   # FastAPI Web Workbench + SSE
python -m hub.cli report <target_id> --format html --out dossier.html
AI_OSINT_HUB_LIVE=1 python -m pytest tests/test_live_smoke.py -q       # network smoke
AI_OSINT_HUB_LIVE=1 python -m pytest tests/test_toolchain_live.py -q   # 32/32 + live tools
AI_OSINT_HUB_LIVE=1 python -m pytest tests/test_native_collectors_live.py -q  # Phase-7 live
```

State lives in `$AI_OSINT_HUB_HOME` (default `~/.ai_osint_hub`) — never inside the
repo. Tests use `tmp_path`/`AI_OSINT_HUB_HOME` fixtures.

## Non-negotiable invariants

1. **Epistemic status is a closed enum** (`hub.models.EpistemicStatus`): CONFIRMED,
   CORROBORATED, SINGLE_SOURCE_LEAD, HYPOTHESIS, CONTRADICTED, COLLECTION_FAILURE.
   Never introduce another status; never hand-write confidence values in engine code
   — use `hub.erkg.confidence.assess`.
2. **Every non-hypothesis claim needs ≥1 immutable artifact** (store enforces this).
   Do not add code paths that create evidence-free claims.
3. **Execution ledger is the duplicate-run guard.** Any pathway that executes a
   capability must go through `InvestigationEngine` (which calls
   `ERKGStore.try_claim_execution` then `record_execution`). Do not spawn tools
   outside `hub/tools/runtime.py`.
4. **Security gates are code-enforced.** `hub.security.policy.check_capability` must
   run before any spawn (runtime does this again). `INTRUSIVE_BLOCKED` never spawns.
   External strings shown to an LLM must pass `hub.security.quarantine`.
5. **No fake tool runs.** Capabilities with missing binaries are reported MISSING and
   filtered from pivots. Never stub a tool result in production code (tests use
   `tests/mock_tools.py`, which is injected — never imported by `hub/`).
6. **Treat the engine transactionally.** One iteration = one SQLite transaction
   (artifact + claims + ledger + hypotheses + counters + `IterationRecord`). Do not
   split it or persist outside the transaction except raw output files.
7. **Every tool run goes through `hub/tools/locator.py` + ToolRuntime.** Never
   hardcode `shutil.which` for tool discovery. Resolution order is managed launcher
   descriptors → `~/.ai_osint_hub/bin` → repo `.venv*` script dirs → host PATH →
   WSL2 bridge (`wsl.exe --exec`) → managed python wrapper. `python -m hub.cli
   doctor` must stay at 32/32 AVAILABLE with real smoke checks on the reference host.
   API-key collectors additionally require credentials; missing keys mark auth
   status but never hide the tool from the 32-tool matrix.
8. **User clues are provenance-bearing seeds; speculative leads are hypotheses.**
   Multi-clue intake (`hub/intake.py`) must keep `USER_PROVIDED_SEED` provenance in
   entity metadata/attributes and seed claims, link every clue to the primary
   subject, and generate bounded (≤6 usernames / ≤4 first+surname emails)
   deterministic transliterated hypotheses with confidence ≤ 0.35 (no stopword
   fragments, no single-first-name generic emails). Hypothesis claims are
   artifact-free planner claims: never route them through the contradiction
   machinery and never create a CONTRADICTED non-hypothesis claim without evidence.

## Architecture gotchas

* `ToolRuntime` is event-loop affine: construct it inside the running loop. The
  engine does this lazily in `_ensure_runner`; do not cache it across `asyncio.run`
  calls.
* `hub/tools/runtime.py` imports `hub.security.policy` lazily to avoid cycles;
  `hub/investigation/reflection.py` imports quarantine lazily for the same reason.
* Windows: `fcntl` does not exist; SQLite WAL + `busy_timeout` replaces lock files.
  Never add a POSIX-only import at module top level.
* Windows consoles: CLI reconfigures stdout to UTF-8; OSINT data can contain any
  Unicode. Keep error paths JSON-safe.
* `tests/mock_tools.py` encodes scripted `ParseOutput` as JSON stdout; the generic
  `parse_mock` parser decodes it. Engine tests inject `runner`, `parser_resolver`
  and `health_probe`; the real registry is swapped by the `isolated_mock_registry`
  fixture and restored on teardown.
* `hub.cooking` is a kept v1 module (NL intake, username/email permutation, phone
  extraction). Its tests are legacy-but-valid; don't refactor it unless necessary.

## Toolchain provisioning gotchas

* **Managed venvs are sandbox-confined on this host.** Python executables inside
  `<repo>/.venv*` can only write inside the workspace. TheHarvester hardcodes
  `~/.local/share/theHarvester` + `~/.theHarvester`, so its manifest sets
  `InvocationSpec.env = {"USERPROFILE": "{tool_home}", "HOME": "{tool_home}"}`.
  Any new tool that writes to the user home needs the same redirect (see
  `hub/tools/capabilities.py::tool_home` / `invocation_env`).
* Managed layouts are **not committed**: `.venv` (Python 3.11 OSINT CLIs),
  `.venv314` (theHarvester, requires Python ≥ 3.12), `.toolhome/`, `.tmp/`, and
  `~/.ai_osint_hub/bin/` are gitignored/provisioned by `doctor --provision`.
* WSL resolution is shell-free: `wsl.exe -d <distro> --exec <tool>` and
  `/usr/bin/which` probes. Do not introduce `bash -lc "..."` quoting bridges —
  Windows→WSL argument quoting mangles `$0`/`$@`.
* WSL probe results are disk-cached at `~/.ai_osint_hub/toolchain_cache.json`
  (TTL 900 s, env `AI_OSINT_HUB_DISK_CACHE=0` disables) so repeated CLI/MCP
  processes do not pay WSL cold-start cost. `doctor` uses `force=True` for
  availability resolution but still benefits from the persisted cache.
* `doctor` smoke success tolerates non-zero exits when a real usage/version banner
  was printed (e.g. `hydra -h` exits 255) but rejects silent failures/tracebacks.
* Python OSINT tools installed in `.venv` need `PYTHONIOENCODING=utf-8`
  (e.g. ghunt's rich banner crashes on cp1252); the runtime env allowlist already
  forwards it.
* **Writable-path placeholders work in flags too**, not just env:
  `capabilities.build_argv` expands `{tool_home}`, `{repo_root}`, `{managed_bin}`
  and creates folders after path flags (`--folderoutput` etc). maigret is fixed
  this way: `--folderoutput {tool_home}/reports` + `USERPROFILE/HOME` redirect,
  because the runtime's temp cwd lives outside the managed-venv sandbox.
* Phase-7 native collectors (`hub/tools/builtin/<tool>.py` +
  `hub/tools/parsers/<tool>.py`) are real httpx public queries, not mocks. They
  must use `hub/tools/builtin/_http.py` (`fetch_safe` manual redirect loop +
  `assert_safe_host` for target-host crawls), stay bounded, and treat 404/no-data
  as a valid empty result. Builtin health = collector+parser importability, which
  is why all 7 count as AVAILABLE without binaries.
* External endpoint quirks discovered by live probes: Ahmia needs the homepage
  anti-bot token before `/search/?q=`, RDAP `rdap.org` redirects to registry
  servers, Gravatar JSON 200/404 distinguishes profiles, keys.openpgp.org only
  accepts e-mail/keyid searches, Wayback CDX can 503/429, GitHub 403 can be
  secondary throttling → classified `RATE_LIMITED`.
* Multi-clue intake gotcha: `example.com/org/net` are legitimate investigation
  targets and must not be treated as common email providers (they are excluded
  from `_COMMON_EMAIL_DOMAINS`); otherwise explicit `allow_domains=["example.com"]`
  tests fail before collection.
* `hub/web.py` is a FastAPI app factory (`create_app(service=None)`) plus embedded
  SPA; `python -m hub.cli serve` is the CLI entrypoint. Tests use `TestClient` with
  an injected mock engine and `wait=true` or background+SSE. SSE polls service
  state every 0.4 s and must terminate at terminal status (or 120 s timeout);
  background runs use `service.create` + `asyncio.to_thread(service.resume)`.
  Starlette may emit an httpx `TestClient` deprecation warning — harmless.
* HTML dossier support lives in `hub/reporting.py::render_html` (standalone,
  print CSS, all untrusted OSINT escaped); CLI/MCP/Web all accept `format=html`.
* **Phase 18 AI, Vision, Analytics & Gruvbox invariants:** `hub/ai/` defaults to
  `enabled=False` (zero-LLM deterministic core untouched); all AI/VLM outputs
  carry `AI_INFERRED` provenance (`direct=False`, confidence ≤ 0.35 reflection /
  ≤ 0.45 VLM) and never inflate to `CONFIRMED`. Config lives at
  `$AI_OSINT_HUB_HOME/ai_config.json` (0600, masked previews, keys registered
  with `redaction.py`; never read `~/.dsh/.credentials.yaml`, `~/.claude/`, or
  `~/.codex/`). Visual/OCR/EXIF text passes `quarantine.sanitize_visual_text` +
  `<untrusted_visual_data>`. New passive collectors (`crtsh_lookup`,
  `asn_bgp_lookup`, `favicon_hash`, `media_forensics`) enforce `fetch_safe` /
  `assert_safe_host` SSRF guards and bring the registry to **32 tools**.
  `hub/erkg/analytics.py` provides pure-Python centrality, communities, bridges,
  `shortest_path`, perceptual-hash clustering, `build_timeline`, and
  `diff_investigations`. `hub/web.py` + `hub/static/vendor/cytoscape.min.js` +
  `hub/reporting.py` + `hub/mcp_server.py` (`ui://ai-osint-hub/workbench.html`)
  default to Gruvbox Material Light (`#fbf1c7`/`#3c3836`/`#af3a03`) with zero
  `innerHTML` and zero `backdrop-filter`.
* **Phase 17 self-test invariants:** USERNAME values must never contain `@`,
  spaces, `/`, URLs or generic slugs (`search-by-username`, `about`, `user(s)`,
  `profil`); the resolver/ingestor enforce this (ingestor reclassifies an
  e-mail-labelled USERNAME as EMAIL). Non-role e-mail local-parts are promoted
  as `EMAIL_DERIVED_USERNAME` seeds and linked to Person; no partial Person like
  `ali` when a structured name exists and no doubled first+handle
  permutations. GitHub e-mail runs must search users + commits, probe
  `/users/<local>`, harvest author/committer logins + repository names and
  hydrate profiles/repos in the same run (never username=email). Ahmia email/
  username results require a literal target/local-part match in title/snippet/
  URL; AZ local phone numbers normalize to `+994…` (E.164) and `00…` to `+…`.
  Sherlock soft-404s include hudsonrock/aniworld/omg.lol/giphy/trello/discord/
  mastodon/mstdn/root URLs; maigret uses `--no-recursion`.
* **Phase 16 signal invariants:** maigret target matching uses full handles only
  (punctuation-normalized: `108.elv1n` == `108_elv1n` == `108elv1n`); never split
  dotted targets into prefixes, and reject root-only or generic-path URLs.
  photon_crawler never emits static/CDN asset URL entities, caps page URL
  entities at 15, and keeps role mailboxes (`info@`, `contact@`, …) as emails
  without identity-link username hypotheses. VirusTotal/ingestor skip
  `None`/blank attribute values. A domain `RESOLVES_TO` IP gives
  `shodan_lookup`/`censys_lookup` (and `rdap_lookup`/`http_headers` on the
  domain) a +0.22 infrastructure bonus and top tier; provider cooldown TTL is
  24h.
* **Phase 15 precision invariants:** free-text usernames require an explicit
  cue (`username:`/`user:`/`handle:`/`nick:`/`nickname:`/`aka`/`goes by`),
  `@handle`, `u/<h>`, or social profile URL path — never bare prose tokens or
  ordinals (`2nd`, `18`, `c2`). Maigret parser drops generic URL paths
  (`about`, `login`, …) and collateral handles unless they match the target;
  URL path is authoritative. `HAS_ATTRIBUTE:role`/internal bookkeeping
  attributes are non-functional via `models.is_functional_predicate`; graph
  layout uses radial springs + circular fit (no x/y wall clamping); fetch
  transient errors are retried silently and clear `#ui-message` on success.
* **Phase 14 coverage/cooldown invariants:** pivot scoring must count a seed as
  covered only when its ledger status is `SUCCESS` (EMPTY/ERROR keep it
  uncovered); attempted-only-empty seeds get the +0.25 `uncovered-seed rescue`,
  and seed entities round-robin one pivot each before repeats. Fast domain
  collectors (`dns_lookup`/`virustotal_lookup`/`tls_cert`/`rdap_lookup`/
  `photon_crawler`) must outrank `theharvester`; sherlock/maigret outrank
  snscrape by prior yield. Provider API tools use `hub.tools.cooldown`
  (`~/.ai_osint_hub/rate_limit_cache.json`, 24h TTL) on `RATE_LIMITED`;
  planner/`available_tool_ids` skip cooling tools and credentials updates clear
  the cache. Web defaults are `max_iterations=16`, `max_tool_calls=20`; graph
  hypothesis/edge-label checkboxes stay unchecked until clicked.
* **Phase 13 hygiene invariants:** `theHarvester` parser strips its banner/config
  logs before any extraction (`cmartorella@edge-security.com`,
  `edge-security.com`, `proxies.yaml`, `api-keys.yaml`) and file/code extensions
  are rejected as DOMAIN/SUBDOMAIN globally (`hub/erkg/resolution.py`). Public
  suffixes include second-level `edu/ac/gov/org/com/net/co/mil/int.<2-letter
  cc>` so `example.edu.az` is a root domain (never `edu.az`); email-derived domains
  are `ASSOCIATED_WITH` the Person, explicit `domains` remain `OWNS`.
  `snscrape` is a python-native builtin probe (no upstream CLI; always exit 0,
  JSONL parser contract). Hypothesis generation skips internal
  `HAS_ATTRIBUTE:clue_field/clue_source/provenance/role/...` claims; Sherlock
  filters its known soft-404 sites.
* **Phase 12 resilience invariants:** `LOCATED_IN` must stay out of
  `FUNCTIONAL_PREDICATES` (hierarchical city/country claims are complementary).
  Engine/pivot must inspect the investigation ledger for `RATE_LIMITED` /
  `AUTHORIZATION_REQUIRED` / `MISSING_BINARY` and pass `blocked_tool_ids` so a
  failed tool is never retried in the same run. Email-derived custom domains use
  provenance `EMAIL_DERIVED_DOMAIN` for seed-wave coverage but are skipped by
  `_derive_scope` (never scope grants; freemail excluded). `github_osint` must
  send standard headers, retry keyless on authenticated primary 401/403, keep
  secondary sub-requests non-fatal, and return EMPTY for 404 users. `maigret`
  needs UTF-8 stdio env plus `tolerate_nonzero_with_stdout`; graph UI hides
  hypotheses/edge labels by default behind explicit toggles.
* **Phase 11 data-quality invariants:** `holehe` parser emits only `[+]`
  positives and **no** `HAS_ATTRIBUTE:registered` on Service entities — the
  ingestor copies relation `metadata` onto the object entity as HAS_ATTRIBUTE
  claims, so relation metadata must stay empty for registration facts; banner
  credits (`megadose`, `@palenath`) and `[-]`/`[x]` lines are ignored. Pivot
  seed-first scoring relies on `entity.metadata.provenance ==
  "USER_PROVIDED_SEED"` and `"USER_DERIVED_HYPOTHESIS"`; seed pivots get +0.35
  and guessed permutations are tiered last/capped at 0.20 corroboration until
  all primary seed types are covered. Seed email domains never auto-populate
  `scope.allow_domains` (only explicit allowlists or DOMAIN/SUBDOMAIN seeds do).
  Intake transliterates diacritics (never strips) and caps hypotheses at
  6 usernames / 4 first+surname emails. Web graph is multi-ring +
  deterministic force relaxation with zoom/pan/type filters; SSE deadline is
  `wall_clock_timeout_sec + 30`, heartbeat 2 s, and the badge must end
  `COMPLETED`.
* **Credentials/secret handling (Phase 10):** vault lives at
  `$AI_OSINT_HUB_HOME/credentials.json` (default `~/.ai_osint_hub`, outside the
  repo) and env vars override it. `hub/credentials.py` loads/registers every
  secret with `hub/security/redaction.py`; runtime redacts stdout/stderr/
  error_message/params before returning, so artifacts/SQLite can never contain a
  raw key. Never print/return raw secrets from API/CLI/Web; only `masked_preview`.
  Saving keys also syncs `<repo>/.toolhome/theharvester/.theHarvester/api-keys.yaml`
  (use `credentials.save_provider()` / `configure_from_mapping()`, both sync).
  HealthStatus/auth statuses: CONFIGURED, KEYLESS_LIMITED (GitHub keyless),
  MISSING_KEY, PARTIAL, OPTIONAL_UNCONFIGURED (ghunt/h8mail until session/config
  exists). `capabilities.capability_auth_ready()` gates pivot selection and the
  runtime returns `AUTHORIZATION_REQUIRED` instead of spawning unauthenticated.
* API endpoint gotchas: Censys Legacy Search (`search.censys.io/api/v2/*`) was
  decommissioned (Sept 30 2026); the provided Censys PAT uses Platform API v3
  (`https://api.platform.censys.io/v3/global/asset/host/{ip}`, Bearer). Platform
  global search needs an org ID (403 for free users) → domain lookups resolve
  A records then fetch host assets. GitHub token uses `Authorization: Bearer`.
  Note `.toolhome/theharvester` YAML intentionally contains raw keys but is
  gitignored; the repo-tracked tests use tmp vaults only.

## Conventions

* Public operations: `investigate`, `step`, `graph`, `tools`, `report` — keep CLI
  and MCP parity through `hub/service.py` only.
* Dossier output must cite `[artifact_id]` + status for every finding; new report
  sections must preserve the Collection Gaps section.
* `DSH_STATE.md` is the autonomous-run log (phases, decisions, verification).
  Update it at the end of each significant work block, not per-edit.
* Prefer implementing behavior in `hub/` modules and adding a focused test in
  `tests/` — do not test via live network except `tests/test_live_smoke.py`.
* Subprocesses (`hub/tools/{runtime,locator}.py`, `hub/toolchain/{doctor,provision}.py`,
  and CLI/shim tests) must pass `stdin=DEVNULL` so piped or non-interactive Windows
  consoles never block or crash (`STATUS_DLL_INIT_FAILED` / closed-stdin hangs).
* On Windows, if `.venv\Scripts\*.exe` (`uv-trampoline`, imports `user32.dll`)
  inherits `Low Mandatory Level` from a sandboxed parent folder and exits `-1073741502`,
  restore Medium integrity via `icacls .\.venv /setintegritylevel "(OI)(CI)M" /T /C /Q`.
* `.github/workflows/ci.yml` runs the offline `pytest -q` matrix on
  `ubuntu-latest` and `windows-latest` for Python `3.11` and `3.13`.
* `pyproject.toml` pins `mcp>=1.0,<2` because `hub/mcp_server.py` uses the
  v1 `mcp.server.fastmcp.FastMCP` API (removed in `mcp 2.x`).

## File layout quick map

```
hub/models.py                    models/enums (single source of truth)
hub/erkg/{resolution,confidence,store,graph,analytics,ingestion}.py
hub/ai/{__init__,models,config,providers,embeddings,reflection_runner}.py
hub/tools/{base,capabilities,locator,runtime}.py + parsers/ + builtin/
hub/toolchain/{doctor,provision}.py + wrappers/   # 32/32 toolchain provisioning
hub/security/{policy,quarantine,redaction}.py
hub/credentials.py               API-key vault, auth status, theHarvester YAML sync
hub/investigation/{hypotheses,pivot,stopping,reflection,engine}.py
hub/reporting.py                 dossier (md+json+Gruvbox print-ready html)
hub/intake.py                    multi-clue seeds, USER_PROVIDED_SEED, permutations
hub/web.py + hub/static/         FastAPI Gruvbox workbench + vendored Cytoscape.js
hub/service.py                   shared operations (CLI+MCP parity)
hub/cli.py, hub/mcp_server.py, hub/orchestrate.py (legacy shim)
tests/                           pytest suite, fixtures, mock_tools.py, support.py
```
