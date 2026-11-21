# AI OSINT Hub v2

**Autonomous, evidence-cited OSINT investigation** — from a target seed to a
provenance-backed intelligence dossier. Not a bag of tool wrappers: the system's
value is how it **thinks, remembers, correlates and pivots**.

The v2 rewrite (previous release was the v1 JSON-file orchestrator) delivers five
architectural pillars:

| # | Pillar | What it means in practice |
|---|--------|---------------------------|
| 1 | **Epistemic Memory & ERKG** | SQLite/WAL Entity-Resolved Knowledge Graph. Every entity attribute and relationship is a `Claim` citing immutable `EvidenceArtifact` records with a closed `EPISTEMIC_STATUS` enum and deterministic confidence. Execution ledger guarantees zero duplicate runs. Crash-safe, resumable. |
| 2 | **Hypothesis-Driven Pivot Engine** | Explicit `CORROBORATION`/`RESOLUTION`/`EXPANSION`/`IDENTITY_LINK`/`VERIFICATION` hypotheses. Every `(entity, tool)` pivot is scored with a mathematical formula including hop-distance scope control. Deterministic stopping conditions. |
| 3 | **Single-Source-of-Truth Tool Registry** | Pydantic capability manifests auto-generate LLM tool schemas, MCP definitions and CLI tables. Two-stage output pipeline: deterministic parsers → normalized delta → quarantine-safe LLM reflection. 28 capabilities, real async subprocess execution, cross-platform. |
| 4 | **Hardened Security** | argv-only `create_subprocess_exec` (no shell), scrubbed environment, isolated scratch dirs, hard process-tree kill on timeout, semaphores + token buckets, code-enforced scope gate, `INTRUSIVE_BLOCKED` capabilities never spawn, indirect-prompt-injection quarantine around all external OSINT text. |
| 5 | **MCP + CLI Parity & Evidence-Cited Dossier** | The same five operations over CLI and MCP (stdio): `investigate`, `step`, `graph`, `tools`, `report`. Every report claim cites its `[artifact_id]` and status, with a dedicated Collection Gaps / Dead Ends / Unverified Hypotheses section. |

---

## Architecture

```
                          ┌──────────────────────────────┐
   raw intel ───────────► │  Intake + seed artifact      │
                          └──────────────┬───────────────┘
                                         ▼
        ┌────────────────────────────────────────────────────────────┐
        │  Plan: explicit hypotheses (CORROBORATION / RESOLUTION /   │
        │        EXPANSION / IDENTITY_LINK / VERIFICATION)          │
        └────────────────────────────┬───────────────────────────────┘
                                     ▼
        ┌────────────────────────────────────────────────────────────┐
        │  Score pivots:                                             │
        │  w1·ExpectedInfoGain + w2·CorroborationValue               │
        │  − w3·HopDistancePenalty − w4·ExecutionCost                │
        │  (ledger filters already-executed pairs)                   │
        └────────────────────────────┬───────────────────────────────┘
                                     ▼
        ┌────────────────────────────────────────────────────────────┐
        │  Execute: ToolRuntime (argv, env scrub, semaphores,        │
        │  token bucket, timeout + process-tree kill, policy gate)   │
        └────────────────────────────┬───────────────────────────────┘
                                     ▼
        ┌────────────────────────────────────────────────────────────┐
        │  Stage 1 parse: deterministic parser → ParseOutput         │
        │  (entities + relations + evidence snippets)                │
        └────────────────────────────┬───────────────────────────────┘
                                     ▼
        ┌────────────────────────────────────────────────────────────┐
        │  Normalize/Correlate: entity resolution + alias merge,     │
        │  evidence-backed claims, deterministic confidence,         │
        │  contradiction detection, execution ledger                 │
        └────────────────────────────┬───────────────────────────────┘
                                     ▼
        ┌────────────────────────────────────────────────────────────┐
        │  Reflect: quarantine-safe LLM packet (optional; the        │
        │  deterministic loop never requires an LLM)                 │
        └────────────────────────────┬───────────────────────────────┘
                                     ▼
        stop?  ── no ──► loop back to Plan
          │
          yes
          ▼
   Evidence-cited dossier (Markdown + JSON)
```

Persistent state lives in SQLite (`hub/erkg/store.py`) with:

```
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;
```

Every engine iteration commits **atomically** (artifact → claims → ledger →
hypotheses → counters → iteration record), so a killed process resumes from the
last committed iteration. `try_claim_execution()` makes a pivot invocation
exclusive across threads/processes: a second worker observes the in-flight
ledger row and never duplicates the tool run.

---

## Install

```bash
# Python 3.10+ (tested on Python 3.14 / Windows 11 and Linux)
cd ai_osint_hub
python -m pip install -r requirements.txt      # pydantic, httpx, mcp
python -m pip install -e .                     # optional: ai-osint-hub console script
```

External OSINT binaries are **optional**. The python-native passive collectors
(`dns_lookup`, `http_headers`, `tls_cert`) always work with no extra installs.
Check what is actually available on this host:

```bash
python -m hub.cli tools      # fast view of declared capabilities
python -m hub.cli doctor     # real --version/--help smoke check per tool
```

Missing binaries are reported as `MISSING` and are never mocked or faked.

## Toolchain provisioning & resolution (28/28)

`python -m hub.cli doctor --provision` installs and smoke-verifies the complete
toolchain; `python -m hub.cli doctor` re-checks it. On the reference Windows host
this yields **28/28 AVAILABLE and smoke-healthy** with credential auth status per provider.

Tool binaries are resolved in this priority order (`hub/tools/locator.py`):

1. **Managed launcher descriptors** — shell-free
   `~/.ai_osint_hub/bin/<tool>.launcher.json` → `python -m hub.toolchain.wrappers.<tool>`
   (real httpx passive implementations used only when the upstream package cannot
   run on a supported interpreter).
2. **Managed native executables** — `~/.ai_osint_hub/bin` and the managed venv
   script dirs (`<repo>/.venv/Scripts`, `<repo>/.venv314/Scripts`, or `bin` on
   POSIX). These are prepended to lookup automatically, so a freshly installed
   binary is found without restarting the shell/Windows PATH.
3. **Host PATH** (`shutil.which`).
4. **WSL2 transparent bridge** (Windows): if a Linux tool exists in the WSL
   distro, it is executed as
   `wsl.exe -d <distro> --exec <tool>` with `shell=False` on the Windows side.
5. **Packaged python wrapper fallback** (last resort; real network queries, never
   mock data).

Provisioning layers used by `--provision`:

| Layer | Tools | Notes |
|---|---|---|
| Managed venv `.venv` (Python 3.11) | `holehe`, `maigret`, `h8mail`, `sherlock`, `ghunt` | installed with `uv pip` (falls back to `python -m pip`); real upstream CLIs. `snscrape` is now python-native |
| Managed venv `.venv314` (Python 3.14) | `theHarvester` | upstream requires Python ≥ 3.12 |
| `~/.ai_osint_hub/bin` | `phoneinfoga` | official Windows x86_64 release download |
| WSL2 Ubuntu (apt) | `whatweb`, `hashcat`, `hydra` | bridged via `wsl.exe --exec`; `hydra` stays `INTRUSIVE_BLOCKED` |
| Host PATH | `nmap`, `amass`, `gobuster` | already provisioned on the reference host |
| Python-native | `dns_lookup`, `http_headers`, `tls_cert` | no binaries required |

Writable per-tool config/state is redirected to `<repo>/.toolhome/<tool>` through
trusted manifest env placeholders (`{tool_home}`) — this keeps sandboxed managed
venvs working and isolates tool config from the user's home directory.

---

## Quickstart

```bash
# 0. Toolchain: verify all 28 tools with real smoke checks; install missing ones
python -m hub.cli doctor
python -m hub.cli doctor --provision

# 1. Capability/health inventory (binaries, python collectors, API keys)
python -m hub.cli tools

# 2. Autonomous investigation with hard budgets
python -m hub.cli investigate "hamid091 example.com target@example.com" \
    --max-iterations 8 --max-tool-calls 12 --timeout-sec 300 \
    --report md --out reports/case.md

# 3. Drive the loop manually (agent-in-the-loop):
python -m hub.cli status <target_id>                # ranked pivots + open hypotheses
python -m hub.cli step <target_id> --action piv_xxx # execute exactly one pivot
python -m hub.cli graph <target_id> --view entities
python -m hub.cli graph <target_id> --view contradictions
python -m hub.cli report <target_id> --format json --out reports/case.json

# 4. List stored investigations
python -m hub.cli list
```

State directory: `$AI_OSINT_HUB_HOME/investigations/<target_id>/erkg.sqlite3`
(defaults to `~/.ai_osint_hub`). Each investigation is self-contained and portable.

A minimal safe live smoke test against an RFC-2606 reserved domain:

```bash
python -m hub.cli investigate "example.com" --max-iterations 3 --max-tool-calls 4 \
    --allow-domain example.com --json
```

---

## MCP server (stdio)

Start the server:

```bash
python -m hub.mcp_server
```

Client configuration (Claude Desktop / `dsh` web profile / any MCP client):

```json
{
  "mcpServers": {
    "ai-osint-hub": {
      "command": "python",
      "args": ["-m", "hub.mcp_server"],
      "cwd": "/absolute/path/to/ai_osint_hub"
    }
  }
}
```

Exposed MCP tools (same semantics as the CLI):

| MCP tool | Purpose |
|---|---|
| `investigate(raw_input, max_iterations, max_tool_calls, wall_clock_timeout_sec, min_pivot_threshold, allow_active_recon, allow_domains, include_report)` | autonomous loop with budgets (passive-only by default) |
| `step(target_id, pivot_id?)` | one Plan→Execute→Normalize→Correlate→Reflect cycle |
| `status(target_id)` | current state, objectives, ranked pivots, open hypotheses |
| `graph(target_id, view)` | `summary`, `entities`, `claims`, `contradictions`, `hypotheses`, `ledger`, `provenance`, `json` |
| `tools(refresh)` | live health check of every capability |
| `doctor(provision=False)` | per-tool resolution + real `--version`/`--help` smoke check (optionally provision) |
| `report(target_id, format)` | evidence-cited Markdown / JSON dossier |

See [docs/MCP_USAGE.md](docs/MCP_USAGE.md) for the full reference.

---

## API credentials & auth (Phase 10)

Five official passive APIs are wired in: **GitHub** (token raises 60 → 5,000 req/h),
**VirusTotal**, **Shodan**, **Censys** and **Hunter.io**. Configure keys in either
place — never edit files by hand:

```bash
# CLI
python -m hub.cli auth status
python -m hub.cli auth set github github_pat_…
python -m hub.cli auth set virustotal <key>
python -m hub.cli auth set shodan <key>
python -m hub.cli auth set censys <api_id> --censys-secret <api_secret>
# or a Censys Platform PAT:
python -m hub.cli auth set censys <censys_pat> --censys-token <censys_pat>
python -m hub.cli auth set hunter <key>
```

Or open the Web Workbench and click **API Keys** in the top bar → password-masked
inputs with green/amber **Configured / Not Set** badges → **Save & Sync Keys**.

- Vault: `~/.ai_osint_hub/credentials.json` (outside the repository, mode 0600
  where supported); env vars override vault values.
- Secrets are registered with a redaction filter and replaced with
  `[REDACTED:<PROVIDER>]` in raw tool output, error messages, evidence artifacts,
  SQLite, CLI/Web output. The UI/CLI only ever show masked previews.
- Saving keys syncs `<repo>/.toolhome/theharvester/.theHarvester/api-keys.yaml`
  (gitignored) so theHarvester uses them automatically inside its sandboxed HOME.
- Auth statuses in `tools`/`doctor`: `CONFIGURED`, `KEYLESS_LIMITED` (GitHub
  without token), `MISSING_KEY`, `PARTIAL` (e.g. Censys ID without a usable
  secret/PAT), `OPTIONAL_UNCONFIGURED` (ghunt/h8mail sessions). The pivot planner
  skips unconfigured tools instead of wasting budget; all 28 stay in the matrix.

## Multi-clue subject intake (Phase 8)

`investigate` accepts either a messy paragraph or structured seed fields and
builds a complete, linked ERKG seed set in iteration 0:

```bash
python -m hub.cli investigate \
  "Target is Linus Torvalds, goes by torvalds, works at Linux Foundation in Portland, \
   domain kernel.org, contact linus@kernel.org, phone +14155552671" \
  --report md

python -m hub.cli investigate "" \
  --name "Linus Torvalds" --username torvalds --email linus@kernel.org \
  --domain kernel.org --phone +14155552671 --org "Linux Foundation" \
  --location Portland --report md
```

- Every extracted clue (`PERSON, USERNAME, EMAIL, DOMAIN, SUBDOMAIN, IP, URL,
  PHONE, ORGANIZATION, LOCATION`) is initialized with
  **`USER_PROVIDED_SEED` provenance** (`entity.metadata.provenance`,
  `HAS_ATTRIBUTE:provenance` claim, seed evidence artifact) and linked to the
  primary subject so `shares_corroborated_identifier` and hop-distance scoring
  work across all user clues.
- The bounded permutation engine deterministically generates username/email
  `HYPOTHESIS` entities (confidence ≤ 0.35) from the person name + supplied
  organization/domain, capped at 20 usernames / 10 emails, linked to the subject
  for passive-collector pivoting. No LLM involved.

The same structured fields are exposed via MCP (`investigate(... name=, usernames=,
emails=, domains=, phones=, organizations=, locations=, urls=, ips=)`) and the
Web API.

---

## Web Workbench (Phase 9)

```bash
python -m hub.cli serve --host 127.0.0.1 --port 8000
# → http://127.0.0.1:8000
```

The FastAPI server (`hub/web.py`) serves an embedded dark-mode single-page
**AI OSINT Hub Intelligence Workbench** (Tailwind CDN + vanilla JS, no Node build):
multi-clue intake drawer with Quick/Standard/Deep budget presets and scope
allowlist, interactive colour-coded ERKG graph (click nodes/edges for evidence
snippet + SHA-256 + epistemic badge), live telemetry/hypotheses/contradictions
tabs streaming over SSE, 1-click “Run Next Pivot”, and dossier viewer with
`.md`/`.json`/print-ready `.html` exports.

| Endpoint | Purpose |
|---|---|
| `GET /` | Workbench SPA |
| `GET /api/tools`, `POST /api/doctor` | Live 28/28 capability + toolchain health |
| `GET /api/credentials`, `POST /api/credentials` | Masked API-key status / save keys, sync theHarvester config |
| `POST /api/investigations` | Start (background + SSE) or run synchronously (`wait=true`) with raw intel + structured seeds + budgets/scope |
| `GET /api/investigations` | Saved investigations list |
| `GET /api/investigations/{id}` | Full state: entities, claims, contradictions, hypotheses, ledger, pivots, graph nodes/edges, artifact index |
| `GET /api/investigations/{id}/stream` | SSE snapshot/iteration/ledger/graph_delta/done events |
| `POST /api/investigations/{id}/step` | Manual agent-in-the-loop pivot execution |
| `GET /api/investigations/{id}/report?format=md|json|html` | Dossier export (HTML is standalone print-ready) |

`python -m hub.cli report <id> --format html --out dossier.html` produces the same
standalone HTML dossier from the CLI.

---

## Phase 11 data-quality & graph UX

- **holehe precision:** only explicit `[+]` lines create `Service` nodes and
  `email REGISTERED_ON service` edges. `[-]`/`[x]` lines, banner/author credits
  (`@palenath`, `megadose`, BTC/legend/footer text) and profile URLs outside a
  positive context are ignored. Registration is **relationship-only** — never a
  global `HAS_ATTRIBUTE:registered` on shared service nodes, so different emails
  can no longer fabricate contradictions.
- **Seed-first pivoting:** user-supplied `USER_PROVIDED_SEED` entities receive a
  `+0.35` expansion bonus plus uncovered-seed-type/new-tool wave bonuses and
  always rank above guessed `HYPOTHESIS` permutations. Guessed permutations have
  corroboration capped at `0.20` and are tiered last until every primary seed
  type (username/email/phone/domain/ip/url) has been expanded by at least one
  tool. Seed emails no longer auto-lock `scope.allow_domains`.
- **High-precision intake:** Azerbaijani/Turkish/Latin diacritics transliterate
  with digraph + ASCII variants (`Taşkin` → `tashkin`/`taskin`; never
  `takin`). Stopword fragments (`elvin_in`, `in_elvin`) and single-first-name
  generic emails (`elvin@gmail.com`) are banned. Hypotheses are bounded to
  **6 usernames / 4 first+surname emails**; organizations/locations split on
  commas/semicolons/newlines, handles split on whitespace.
- **Web Workbench:** multi-ring concentric + force-relaxed graph with mouse-wheel
  zoom, drag-to-pan, Zoom +/−/Reset, node search and clickable entity-type filter
  pills; clean empty intake defaults + Clear Form + red error banner; SSE
  deadline = investigation `wall_clock_timeout_sec` + 30 s with 2 s heartbeats,
  and the status badge settles to **COMPLETED** with the dossier loaded once the
  investigation is terminal.

## Phase 12 resilience & semantic fixes

- **Hierarchical locations:** `LOCATED_IN` is no longer a functional
  single-value predicate — `Baku`, `AZ` and `"Baku, AZ"` are complementary
  hierarchy claims, never contradictions. `--location "Baku, AZ"` expands to
  `"Baku, AZ"`, `Baku`, `AZ`, so phoneinfoga's country-level hit corroborates
  the seeded city/country instead of tainting the subject.
- **In-run tool circuit breaker:** once a tool records `RATE_LIMITED`,
  `AUTHORIZATION_REQUIRED` or `MISSING_BINARY` in an investigation's ledger it
  is excluded from every subsequent pivot selection in that run (engine +
  pivot scorer), stopping wasted tool-call budgets.
- **Institutional mail-domain seed wave:** a non-freemail domain extracted from
  an email seed (e.g. `example.edu.az`) is promoted to the seed wave so
  `rdap_lookup`, `dns_lookup`, `tls_cert`, `photons_crawler`/`virustotal_lookup`
  are scheduled alongside username/email/phone pivots. It is tagged
  `EMAIL_DERIVED_DOMAIN` and **never auto-populates `scope.allow_domains`**.
- **GitHub resilience:** standard GitHub headers (`Accept`,
  `X-GitHub-Api-Version: 2022-11-28`, `User-Agent: ai-osint-hub`); an
  authenticated primary 401/403 retries keyless; repos/events/commit-search
  sub-request 403/422s are warnings (never discard a good profile or produce a
  false `RATE_LIMITED`); nonexistent usernames return a clean EMPTY result.
- **maigret hardening:** UTF-8 stdio (`PYTHONIOENCODING`/`PYTHONUTF8`,
  `NO_COLOR`) plus explicit `tolerate_nonzero_with_stdout` means a completed
  scan with site warnings no longer becomes `NONZERO_EXIT`.
- **Graph de-clutter:** **Show Hypotheses (N)** toggle default **OFF**
  (unverified HYPOTHESIS nodes hidden, count shown), **Show Edge Labels**
  default **OFF**, wider inner/outer rings and stronger repulsion so labels no
  longer collide; node inspector still hover/click available.

## Phase 13 data-hygiene fixes

- **theHarvester banner/config filtering:** author banner
  (`cmartorella@edge-security.com`, `edge-security.com`, `Christian
  Martorella`), config-log lines (`Read proxies.yaml…`, `api-keys.yaml`) and
  legend/section headers are stripped before parsing; those identifiers are
  never ingested unless the target itself is `edge-security.com`. Config/code
  filenames (`.yaml`, `.json`, `.py`, `.sqlite`, `.html`, images, …) are
  rejected globally as DOMAIN/SUBDOMAIN values.
- **Multi-part public suffixes:** second-level country suffixes
  (`edu.<cc>`, `ac.<cc>`, `gov.<cc>`, `org.<cc>`, `com.<cc>`, `net.<cc>`,
  `co.<cc>`, `mil.<cc>`, `int.<cc>`) are public suffixes. `example.edu.az` is a
  **root DOMAIN**, never a parent `edu.az`; `mail.example.edu.az` is its subdomain.
  Email-derived domains link to the Person with `ASSOCIATED_WITH`; only
  explicitly provided `domains` get `OWNS`.
- **snscrape replaced:** the broken upstream Twitter/X CLI (always exit 2) is
  no longer invoked. A zero-auth native httpx probe queries GitLab, Reddit,
  Keybase, HackerNews, Lichess, Chess.com, Dev.to, Mastodon and Medium, emits
  JSONL matching the snscrape parser, and always reports exit 0 (clean EMPTY
  when nothing is found).
- **Hypothesis hygiene & Sherlock soft-404s:** internal bookkeeping attributes
  (`HAS_ATTRIBUTE:clue_field`, `clue_source`, `provenance`, `role`,
  `seed_wave`, `derived_from_email`) never generate CORROBORATION hypotheses.
  Sherlock v0.16 known soft-404 sites (`7cups`, `f3.cool`, `houzz`,
  `forums.envato.com`) are filtered from claimed profiles.

## Phase 14 seed coverage, provider cooldown & budget defaults

- **Uncovered-seed rescue:** a seed username/domain that has only produced
  `EMPTY`/`ERROR` runs gets a **+0.25 rescue bonus** for its next highest-prior
  tool, and the pivot order now round-robins across all seed entities (one pivot
  per seed before any seed gets a second). Two usernames plus an email, phone and
  institutional domain therefore all receive coverage inside a 10-call budget.
- **Fast domain first:** `dns_lookup`, `virustotal_lookup`, `tls_cert`,
  `rdap_lookup` and `photon_crawler` get a **+0.25 fast-domain bonus** (+0.12 for
  the highest-yield DNS/VT/TLS trio) so they run at or above slow `theharvester`;
  `sherlock`/`maigret` retain their higher prior yield over `snscrape` on seed
  usernames. Free-text intake now preserves dotted handles such as `108.elv1n`
  instead of splitting them into `108`/`elv1n`.
- **Provider cooldown:** when `hunter_lookup`, `censys_lookup`, `shodan_lookup`
  or `virustotal_lookup` returns `RATE_LIMITED` (e.g. Hunter HTTP 429
  `restricted_account`), a **24-hour cross-run cooldown** is recorded in
  `$AI_OSINT_HUB_HOME/rate_limit_cache.json`. New investigations skip cooling
  tools immediately; changing credentials through the Web API Keys drawer or
  `python -m hub.cli auth set` (and `hub.tools.cooldown.reset_cache()`) clears
  the cache.
- **Web budget defaults:** `max_iterations=16` (was 10), `max_tool_calls=20`;
  **Show Hypotheses** and **Show Edge Labels** render unchecked and `Clear`
  resets them to unchecked/false.

## Phase 15 precision & layout hardening

- **Strict free-text handles:** a `USERNAME` seed is inferred only from an
  explicit `@handle`, a labeled cue (`username:`, `user:`, `handle:`, `nick:`,
  `nickname:`, `aka`, `goes by`), `u/<handle>`, or a known social profile URL
  path. Bare prose tokens and ordinals (`2nd`, `18`, `c2`, `sha256`, …) are never
  promoted; a raw input that is exactly one handle (e.g. `investigate hamid091`)
  still works. Explicit cues may list multiple handles (`goes by a and b`).
- **maigret target filtering:** claimed profiles must match the queried target
  by URL path or handle; generic paths (`youtube/about`, login/search/help, …)
  and recursive collateral usernames (`shame`, `humidify`, `about`) are dropped.
  The URL path is authoritative, so a payload sidebar username cannot pollute
  the subject.
- **Multi-valued role attributes:** `HAS_ATTRIBUTE:role` (and
  `clue_field`/`clue_source`/`provenance`/`seed_wave`/`derived_from_email`) is
  non-functional; a domain can be both `mail_domain` and `registrable_parent`
  with zero contradictions. Other attributes such as `registered` remain
  functional.
- **Radial graph layout:** nodes are anchored to concentric ring targets with a
  strong radial spring plus repulsion/edge springs, then fitted by a circular,
  aspect-preserving `maxRadius` scale. Independent x/y wall clamps are gone, so
  150+ nodes never form a square border along the canvas walls.
- **Transient fetch UX:** network hiccups (`Failed to fetch`, `NetworkError`) are
  retried silently during active investigations; `#ui-message` is cleared on
  successful graph/state/dossier loads and on RUNNING/COMPLETED transitions.

## Phase 16 signal hygiene

- **Full-handle maigret matching:** target comparison uses only full-handle
  forms (`108.elv1n`, `108_elv1n`, `108-elv1n`, `108elv1n`); dotted targets are
  never split into partial tokens (`108`, `elv1n`). Root-only URLs
  (`https://discord.com`) and generic paths (`youtube/about`, login/search/
  settings/contact/privacy/terms/feed/share/intent, …) are rejected.
- **photon_crawler assets:** static theme/media/script/font URLs (`.css`, `.js`,
  `.mjs`, `.map`, images, fonts, video, archives) and third-party CDN hosts
  (`code.jquery.com`, `cdnjs.cloudflare.com`, `fonts.gstatic.com`,
  `cdn.jsdelivr.net`, `unpkg.com`, …) never become `URL` entities. At most **15
  high-signal internal page URLs** are emitted per crawl; subdomains, emails
  and social profiles are still collected. Role mailboxes (`info@`, `contact@`,
  `admin@`, …) are kept as emails but never spawn `username:info` identity
  hypotheses.
- **Empty attributes:** VirusTotal parser and the ERKG ingestor drop `None` and
  blank/whitespace attribute values, so no `HAS_ATTRIBUTE:* -> ""` claims.
- **Resolved-IP pivots:** once a root domain has a `RESOLVES_TO` IP, Shodan and
  Censys on the primary IP (plus RDAP and HTTP headers on the domain) receive a
  **+0.22 infrastructure bonus** and top priority, outranking low-yield
  `darkweb_ahmia`/`pgp_keyserver`/secondary username or email probes. Provider
  rate-limit cooldowns are now **24 hours** and still clear on credential update
  or `reset_cache()`.

## Phase 17 self-test signal fixes

- **USERNAME guard:** usernames can never be e-mail addresses, URLs, paths or
  generic slugs (`search-by-username`, `about`, `user(s)`, `profil`, …). The
  resolver drops invalid USERNAME drafts and the ingestor reclassifies an
  e-mail-labelled USERNAME as EMAIL. Sherlock additionally filters
  `aniworld`, `hudsonrock`, `rusfootball`, `patched.sh`, `omg.lol`,
  `boardgamegeek`, `giphy`, `trello`, `discord`, `mastodon.cloud/xyz`,
  `mstdn.io/social` and root-only profile URLs; maigret runs with
  `--no-recursion`.
- **Email-derived handle:** a non-role e-mail local-part (`kamranmammadov01`,
  after stripping `.std`) becomes an `EMAIL_DERIVED_USERNAME` primary seed
  (confidence 0.64) linked `Person HAS_USERNAME`, so GitHub/Sherlock/Maigret/
  snscrape scan it immediately. Generic role mailboxes (`info`, `admin`,
  `contact`, `support`, …) are excluded. Partial name tokens are never mined as
  a second Person when a structured name exists, and overlapping tokens cannot
  produce doubled handles (`kamran.kamranmammadov01`).
- **GitHub email pivot:** `github_osint` on an e-mail queries
  `/search/users?q=<email> in:email` plus
  `/search/commits?q=author-email:<email>&per_page=10`, passively probes the
  e-mail local-part via `/users/<local>`, collects every author/committer login
  and repository, and hydrates `/users/<login>` plus
  `/users/<login>/repos?per_page=30&sort=updated` in the same run. Results emit
  the login and repositories with `OWNS`, never the e-mail as a username.
- **Ahmia exact match:** e-mail/username searches keep a `.onion` result only
  if the full e-mail or distinctive local-part (length ≥5) literally appears in
  its title/snippet/URL; `gmail.com`-only dark-web shop hits are dropped.
- **Phone E.164:** Azerbaijan local numbers (`0501234567`, `051…`, `055…`,
  `070…`, `077…`, `099…`, `010…`) normalize to `+994501234567` when AZ/Baku
  context or the mobile prefix applies; generic `00…` prefixes normalize to
  `+…`. Phoneinfoga therefore receives E.164 from intake/pivot params.

## Epistemic trust model

Every claim has **exactly one** status (closed enum — no free-text statuses):

| Status | Meaning | Deterministic confidence |
|---|---|---|
| `CONFIRMED` | ≥2 independent tools agree, all direct, confidence ≥ 0.90 | formula below |
| `CORROBORATED` | ≥2 independent tools agree | `0.85 + 0.05·(n−2) + 0.15·(avg_rel−0.5)`, capped at 0.99 |
| `SINGLE_SOURCE_LEAD` | exactly one source | `min(0.65, 0.10 + 0.60·reliability)` |
| `HYPOTHESIS` | planner-generated, no artifact yet | ≤ 0.40 |
| `CONTRADICTED` | functional claims disagree | 0.30 (both claims retained) |
| `COLLECTION_FAILURE` | run failed / no evidence | 0.0 |

"Independent" means a different `tool_id` — re-running the same tool (impossible
through the ledger) never adds corroboration. A **functional predicate** (e.g.
`HAS_EMAIL`, `HAS_ATTRIBUTE:registered`) conflicting across sources produces a
`Contradiction` record; both claims become `CONTRADICTED` and appear in the
report's contradiction section.

Every attribute/relationship claim cites at least one immutable artifact:

```
artifact_id, source_tool, invocation_params_hash, timestamp_utc,
raw_evidence_snippet, raw_output_sha256, parser_version,
epistemic_status, confidence
```

Artifacts are insert-only; the store refuses to tamper with existing ids.

---

## Pivot scoring & stopping

For every candidate `(TargetEntity, ToolCapability)`:

```
Score = w1·ExpectedInfoGain + w2·CorroborationValue
      − w3·HopDistancePenalty − w4·ExecutionCost
```

* `ExpectedInfoGain` = tool prior yield × uncertainty × novelty (ledger-aware).
* `CorroborationValue` = 1.0 if the pivot can verify/refute an OPEN hypothesis,
  0.6 for entities with unverified claims, 0.8 for contradictions.
* `HopDistancePenalty` = 0 for ≤2 hops from the seed; `0.5 + 0.25·(hop−2)` beyond,
  reduced ×0.2 when the entity shares a **corroborated identifier** with the seed
  (prevents six-degrees-of-separation scope explosion).
* `ExecutionCost` = normalized timeout + active-recon/authorization surcharges.

Defaults: `w1=0.45, w2=0.30, w3=0.15, w4=0.10` (normalized), `min_pivot_threshold=0.12`.
The loop halts deterministically when **all pivots are below the threshold**, when
**all core objectives are CORROBORATED/CONFIRMED**, or when a **hard budget**
(`max_iterations`, `max_tool_calls`, `wall_clock_timeout_sec`) is exhausted.

Hypotheses that are still open when the budget runs out are marked `INCONCLUSIVE`
and listed in the dossier — never silently dropped.

---

## Capability matrix

28 capabilities declared as strict Pydantic manifests (`hub/tools/capabilities.py`).
Modes: `PASSIVE`, `ACTIVE_RECON`, `INTRUSIVE_BLOCKED`. Run `python -m hub.cli tools`
for live availability on your host; on the reference host all 28 are provisioned
and smoke-healthy (`python -m hub.cli doctor`).

| Tool | Mode | Accepts | Produces | Host binary |
|---|---|---|---|---|
| `dns_lookup` | PASSIVE | domain, subdomain | ip | python-native (always) |
| `http_headers` | PASSIVE | domain, url | url, service | python-native (always) |
| `tls_cert` | PASSIVE | domain, subdomain | subdomain, organization | python-native (always) |
| `holehe` | PASSIVE | email | service, username | `holehe` |
| `maigret` | PASSIVE | username | service, social_profile | `maigret` |
| `h8mail` | PASSIVE | email | breach_record, email | `h8mail` |
| `theharvester` | PASSIVE | domain, email | email, domain, subdomain, ip, url | `theHarvester` |
| `sherlock` | PASSIVE | username | social_profile, service | `sherlock` |
| `ghunt` | PASSIVE | email | social_profile, username, service | `ghunt` |
| `phoneinfoga` | PASSIVE | phone | organization, location, service | `phoneinfoga` |
| `snscrape` | PASSIVE | username | social_profile, url | python-native public profile probe (GitLab, Reddit, Keybase, HackerNews, Lichess, Chess.com, Dev.to, Mastodon, Medium) |
| `nmap` | ACTIVE_RECON | ip, domain, subdomain | ip, port, service | `nmap` |
| `amass` | ACTIVE_RECON | domain | subdomain, ip, asn, organization | `amass` (OAM graph stdout parsed; passive enum ~2 min) |
| `gobuster` | ACTIVE_RECON | url, domain | url | `gobuster` (+ wordlist) |
| `whatweb` | ACTIVE_RECON | domain, url | service, url | `whatweb` |
| `hashcat` | ACTIVE_RECON (authorization required) | hash | credential | `hashcat` |
| `hydra` | **INTRUSIVE_BLOCKED** | service | credential | never spawned without explicit `allow_intrusive` |
| `photon_crawler` | PASSIVE | domain, url | url, email, subdomain, social_profile, service | python-native (root + robots.txt + sitemap.xml, SSRF-safe redirects) |
| `github_osint` | PASSIVE | username, email | social_profile, person, organization, location, url, email, repository | python-native (public GitHub REST API) |
| `gravatar_lookup` | PASSIVE | email | social_profile, username, person, url | python-native (Gravatar profile JSON) |
| `pgp_keyserver` | PASSIVE | email, username | email, person | python-native (keys.openpgp.org / keyserver.ubuntu.com HKP index) |
| `rdap_lookup` | PASSIVE | domain, ip | organization, email, domain | python-native (rdap.org JSON) |
| `wayback_cdx` | PASSIVE | domain, url | url, subdomain | python-native (Archive.org CDX API) |
| `darkweb_ahmia` | PASSIVE | domain, email, username | url, service | python-native (Ahmia clearnet index, no Tor daemon) |
| `virustotal_lookup` | PASSIVE · key: `VIRUSTOTAL_API_KEY` | domain, ip | subdomain, ip, organization, service | python-native VirusTotal API v3 (passive DNS resolutions, subdomains, ASN/owner, reputation) |
| `shodan_lookup` | PASSIVE · key: `SHODAN_API_KEY` | ip, domain | ip, port, service, subdomain, organization | python-native Shodan REST API (ports, banners, hostnames, ISP/ASN) |
| `censys_lookup` | PASSIVE · key: Censys PAT or ID+Secret | ip, domain | ip, port, service, subdomain, organization | python-native Censys Platform API v3 (`asset/host`, certificate SANs, AS metadata) |
| `hunter_lookup` | PASSIVE · key: `HUNTER_API_KEY` | domain, email | email, person, organization, social_profile | python-native Hunter.io v2 (domain search + email verifier) |

All 28 deterministic parsers/tool adapters have fixture-driven characterisation tests
(`tests/test_parsers.py`, `tests/test_builtin_collectors.py`). Parsers never raise on
garbage output — failures are classified (`PARSE_ERROR`, `EMPTY_RESULT`, `TIMEOUT`,
`MISSING_BINARY`, `RATE_LIMITED`, `SCOPE_BLOCKED`, `INTRUSIVE_BLOCKED`,
`AUTHORIZATION_REQUIRED`, `NONZERO_EXIT`, `SPAWN_ERROR`).

---

## Security model

* **Subprocess safety** — `asyncio.create_subprocess_exec(*argv)`, never a shell
  string; minimal scrubbed environment allowlist; isolated per-investigation
  scratch directory; hard timeout with process-tree termination
  (`killpg` on POSIX, `taskkill /F /T` on Windows).
* **Concurrency** — global semaphore + smaller heavy-local semaphore + per-tool
  token buckets; SQLite WAL + busy timeout for concurrent workers.
* **Passive-first by default.** `ACTIVE_RECON` capabilities do not even enter the
  pivot pool unless active recon is explicitly enabled (`--allow-active-recon` on
  the CLI, `allow_active_recon=True` over MCP, or `scope.allow_active_recon` in
  config). `INTRUSIVE_BLOCKED` capabilities never spawn.
* **Code-enforced scope** — an explicitly supplied allow/deny domain or entity list
  is a hard boundary: an out-of-scope seed is rejected before the investigation
  starts, active targets must match the allowlist (or be public IPs resolved from
  an allowlisted domain), and private/loopback/link-local/cloud-metadata addresses
  are blocked before any spawn. The LLM never decides whether scope is respected.
* **Indirect prompt injection** — all external OSINT text is attacker-controlled.
  It is stripped of ANSI/control characters, tag escapes are neutralized, and it
  is wrapped in `<untrusted_osint_data>…</untrusted_osint_data>` with a system
  prompt forbidding instruction-following inside the tags. The deterministic loop
  never interprets external text as instructions.

---

## Testing & verification

```bash
python -m pytest -q --tb=short          # full deterministic suite (no network)
```

Live passive smoke test (RFC-2606 `example.com`, opt-in):

```bash
AI_OSINT_HUB_LIVE=1 python -m pytest tests/test_live_smoke.py -q
AI_OSINT_HUB_LIVE=1 python -m pytest tests/test_toolchain_live.py -q
```

Test suite layout: ERKG/provenance/WAL/concurrency, entity resolution, confidence
math, parser fixtures, runtime failure modes, security policy matrix, injection
quarantine, pivot-formula units, hypothesis lifecycle, deterministic stopping, and
mock-tool end-to-end engine tests (discovery, cross-tool corroboration,
contradictions, zero duplicate runs across resume, budgets, parse errors,
intrusive-tool exclusion).

---

## Repository layout

```
hub/
  models.py                 canonical Pydantic models + closed enums
  cooking.py                NL intake, username/email permutations (kept from v1)
  erkg/                     resolution, confidence, SQLite/WAL store, graph view,
                            evidence ingestion
  tools/                    capability manifests, parse contract, async runtime,
                            deterministic parsers, python-native collectors
  security/                 scope policy + prompt-injection quarantine
  investigation/            hypotheses, pivot scorer, stopping, reflection, engine
  reporting.py              evidence-cited Markdown/JSON dossier
  service.py                five operations shared by CLI and MCP
  cli.py                    python -m hub.cli
  mcp_server.py             python -m hub.mcp_server (stdio)
  orchestrate.py            legacy v1 CLI compatibility shim
tests/                      deterministic pytest suite + fixtures + mock tools
docs/MCP_USAGE.md           MCP reference
skills/ai-os-orchestrator/  agent-facing operating policy
DSH_STATE.md                autonomous execution log / architecture decisions
```

---

## v1 → v2 migration

The v1 JSON-per-file orchestrator (`hub/orchestrate.py --init/--step/--status/--report`)
was replaced. Existing scripts keep working through a cross-platform shim
(no more POSIX-only `fcntl`; it failed to import on Windows):

```bash
python -m hub.orchestrate --init '{"raw_input":"...","constraints":{"max_depth":5}}'
python -m hub.orchestrate --step '{"target_id":"...","selected_action_id":"act_000"}'
python -m hub.orchestrate --report '{"target_id":"..."}'
```

Legacy `act_NNN` ids are mapped onto the current deterministic `piv_…` ids. New
integrations should use the CLI or MCP operations above.

---

## Honest limitations

* Capabilities whose binaries are not installed are marked `MISSING`; their CLI
  invocations are flagged `invocation_verified: false` in the manifest where the
  flag combination could not be verified on the build host.
* There is no built-in LLM client. The deterministic loop is complete on its own;
  the `reflection` packet is the intended hand-off for an external reasoning model
  through the MCP/CLI caller.
* Automatic contradiction *resolution* is detection-only: the engine records
  contradictions and pivots to collect independent evidence; it never guesses a
  winner.
