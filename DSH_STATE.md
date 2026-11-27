# DSH_STATE.md — Autonomous Execution State Anchor

> **Directive:** DSH AUTONOMOUS EXECUTION DIRECTIVE — AI OSINT HUB (5-phase rebuild)
> **Branch:** `feat/dsh-autonomous-v2` (base commit `58479f9`)
> **Host:** Windows 11, Python 3.14.3, `dsh` harness
> **Rule:** every phase ends with a green verification run + update of this file.

---

## Phase Checklist

- [x] **Phase 1 — Recon & Baseline Audit** (2026-11-14)
- [x] **Phase 2 — ERKG Memory, Provenance & WAL Persistence** (2026-11-14)
- [x] **Phase 3 — Hardened Tool Runtime, Registry & Deterministic Parsers** (2026-11-14)
- [x] **Phase 4 — Hypothesis & Pivot Scoring Engine** (2026-11-14)
- [x] **Phase 5 — MCP Server, CLI, Live Safe Smoke Test & Docs** (2026-11-14)

---

## Phase 1 — Recon & Baseline Audit (DONE)

### Repo baseline
- Source: `https://github.com/hamidaliyev091/ai_osint_hub` @ `58479f9` ("AI OSINT Hub — autonomous OSINT agent runtime").
- ~4,600 LOC Python, 13 tool integrations, 17 regex/JSON parsers, JSON-per-file state, MCP server, 64 tests.
- **Baseline `pytest -q --tb=short` → `64 passed in 0.10s`.**

### Legacy module map
| Module | Lines | Finding |
|---|---|---|
| `hub/orchestrate.py` | 1011 | JSON state dir, `fcntl` file lock, CLI dispatch, all-in-one controller |
| `hub/registry.py` | 423 | ToolMeta dataclass, 14 tools, no Pydantic contract, no health check |
| `hub/executor/runtime.py` | 143 | `subprocess.run`, blocking, no env scrub, no process-tree kill |
| `hub/executor/parsers/*.py` | 17 files | `parse(raw, target) -> list[dict]`; no relations, no evidence refs |
| `hub/graph/memory.py` | 364 | dict graph, no provenance, no claim status, no WAL |
| `hub/cooking.py` | 502 | NL parsing, normalization, hypothesis expansion, confidence constants (keep) |
| `hub/planner/candidates.py` | 424 | ad-hoc 5-factor scoring, no hypothesis objects, no hop-distance math |
| `hub/planner/evaluate.py` | 192 | hard/soft stop strings, no ledger/budget objective model |
| `hub/mcp_server.py` | 132 | FastMCP over POSIX Unix socket; 4 tools only |
| `docs/MCP_USAGE.md`, `skills/.../SKILL.md` | | document legacy 4-op API; no README at repo root |

### Baseline defects (verified on this host)
1. **P0 — `import hub.orchestrate` crashes on Windows:** `ModuleNotFoundError: fcntl` (line 17). Whole CLI + MCP server is non-functional on the host OS.
2. **P0 — POSIX-only state root** `/tmp/ai_osint_hub/state`; no Windows-safe path; no SQLite/WAL, no crash-safe transactional state.
3. **P0 — No epistemic provenance.** Nodes/edges carry no immutable `EvidenceArtifact`, no `EPISTEMIC_STATUS`, no deterministic corroboration math; reports cannot cite evidence.
4. **P0 — No execution ledger.** Duplicate-run prevention is a history scan (substring/equality heuristics); no `(entity, tool, param_hash)` unique record.
5. **P1 — Static candidate heuristic.** No explicit hypotheses, no hop-distance scope control, no corroboration-targeted pivots, no `min_pivot_threshold` / objective-based stopping.
6. **P1 — Tool contract not enforced.** Plain dataclass, mutable global dict, no `execution_mode`, no `binary_or_api_check()`, no rate limits/semaphores, no auto-generated LLM/MCP schemas.
7. **P1 — Security gaps.** No scope allow/deny gate, no indirect-prompt-injection quarantine, no scrubbed env / process-tree kill; all subprocess execution synchronous.
8. **P2 — Parsers raw-string only.** No deterministic relations/evidence snippets, no parse-fixture tests, no error classification (`TIMEOUT`, `MISSING_BINARY`, `RATE_LIMITED`, `PARSE_ERROR`, `EMPTY_RESULT`).
9. **P2 — Tests hardcode `/root/ai_osint_hub`** in every file; no README; no `pyproject.toml`; `requirements.txt` misses `pydantic`, `mcp`, `pytest`.

### Environment facts (this host)
- Installed: `pydantic 2.13.4`, `networkx 3.7`, `pytest 9.0.3`, `httpx 0.28.1`, `rich`, `mcp`, `uvicorn 0.49.0`.
- Missing: `pytest-asyncio` (tests will use `asyncio.run`), `aiosqlite` (use stdlib `sqlite3` + WAL), `dnspython`.
- OSINT binaries on PATH: `nmap`, `amass`, `gobuster`. Missing: `holehe`, `maigret`, `h8mail`, `theHarvester`, `sherlock`, `whatweb`, `ghunt`, `phoneinfoga`, `snscrape`, `hashcat`, `hydra`. `whois`/`dig` absent (WSL side only). → builtin Python-native passive collectors (`dns_lookup`, `http_headers`, `tls_cert`) are required for a real live smoke test.

---

## Canonical Decisions (single source of truth for all phases)

### Module layout (target)
```
hub/models.py                  # Pydantic domain models + enums (EpistemicStatus, EntityType, EdgeType, ...)
hub/erkg/                      # Entity-Resolved Knowledge Graph
  resolution.py                # canonicalization / alias merge (13 canonical types)
  confidence.py                # deterministic confidence + epistemic status
  store.py                     # SQLite WAL persistence: entities, claims, artifacts, ledger, hypotheses
  graph.py                     # in-memory graph view (BFS hops, neighbors) synced from store
hub/tools/
  base.py                      # ParseOutput / EntityCandidate / RelationCandidate / evidence
  capabilities.py              # Pydantic ToolCapability manifests + registry + schema exporters
  runtime.py                   # async subprocess runner (shell=False, env scrub, tree kill, semaphores, token bucket)
  builtin/                     # python-native passive collectors (dns, http, tls)
  parsers/                     # 17 deterministic parsers -> ParseOutput (fixture tested)
hub/security/
  quarantine.py                # indirect prompt-injection sanitize + <untrusted_osint_data> wrapper
  policy.py                    # code-enforced scope gate + intrusive block + SSRF guard
hub/investigation/
  hypotheses.py                # explicit structured hypotheses (CORROBORATION / RESOLUTION / EXPANSION / IDENTITY_LINK)
  pivot.py                     # mathematical pivot scorer (w1..w4, hop penalty, lead boost)
  engine.py                    # Plan -> Execute -> Normalize -> Correlate -> Score -> Reflect loop
  reflection.py                # quarantined LLM context packet + apply LLM proposals
hub/reporting.py               # evidence-cited Markdown + JSON dossier
hub/service.py                 # investigate / step / graph / tools / report operations (CLI+MCP parity)
hub/cli.py                     # python -m hub.cli (5 subcommands)
hub/mcp_server.py              # FastMCP over stdio, same 5 operations
hub/orchestrate.py             # legacy `--init/--step/--status/--report` compatibility shim
hub/cooking.py                 # kept: NL intake, username/email permutation, expand_hypotheses
```

### Storage
- Default state root: `%USERPROFILE%\.ai_osint_hub\investigations\<target_id>\` (override `AI_OSINT_HUB_HOME`), files `erkg.sqlite3` + `raw/`.
- SQLite: `PRAGMA journal_mode=WAL; synchronous=NORMAL; busy_timeout=5000; foreign_keys=ON`.
- One transaction per engine iteration (artifact → claims → ledger → hypotheses → investigation counters), so kill -9 resumes from last committed iteration.
- Tables: `investigations`, `entities`, `entity_aliases`, `artifact` (immutable), `claims`, `claim_artifacts`, `contradictions`, `execution_ledger` (PK: investigation, entity, tool, param_hash), `hypotheses`, `iterations`.

### Epistemic model
- `EpistemicStatus = CONFIRMED | CORROBORATED | SINGLE_SOURCE_LEAD | HYPOTHESIS | CONTRADICTED | COLLECTION_FAILURE` (strict enum, no other values).
- Independent source = unique `tool_id` (seed input counts as source `seed`).
- Deterministic confidence: 0 sources → `COLLECTION_FAILURE` 0.0; 1 source → `min(0.65, 0.10 + 0.60*reliability)` = `SINGLE_SOURCE_LEAD`; ≥2 independent sources → `0.85 + 0.05*(n-2) + 0.10*(avg_reliability-0.5)` capped 0.99 = `CORROBORATED`; `CONFIRMED` when corroborated AND confidence ≥ 0.90 AND direct evidence; conflicts on functional predicates → both claims `CONTRADICTED` (confidence ≤ 0.30).
- Every entity attribute and edge is a `Claim` backed by ≥1 immutable `EvidenceArtifact` (`artifact_id, source_tool, invocation_params_hash, timestamp_utc, raw_evidence_snippet, raw_output_sha256, parser_version, epistemic_status, confidence`).

### Pivot math
`Score = w1*ExpectedInfoGain + w2*CorroborationValue - w3*HopDistancePenalty - w4*ExecutionCost`
defaults `w1=0.45, w2=0.30, w3=0.15, w4=0.10`; hop >2 from seed penalized (0.5 + 0.25/hop, capped 1.0) unless entity shares a corroborated identifier with a seed (penalty ×0.2); open `HYPOTHESIS`/`SINGLE_SOURCE_LEAD` corroboration targets get CorroborationValue 1.0. Stop when every pivot `< min_pivot_threshold` (default 0.12), all core objectives corroborated/confirmed, or budgets exhausted (`max_iterations`, `max_tool_calls`, `wall_clock_timeout_sec`).

### Entry points (final)
```
python -m hub.cli tools
python -m hub.cli investigate "<raw intel>" --max-iterations 10 --max-tool-calls 20
python -m hub.cli step <target_id> [--action piv_003]
python -m hub.cli graph <target_id> [--view entities|claims|contradictions|hypotheses|json]
python -m hub.cli report <target_id> [--format md|json] [--out PATH]
python -m hub.mcp_server            # stdio MCP: investigate, step, graph, tools, report
```

### Verification contract per phase
1. Phase 2 → `pytest -q tests/test_erkg.py tests/test_resolution.py tests/test_confidence.py`; WAL pragmas asserted; crash-resume test.
2. Phase 3 → parser fixture suite (all 17 parsers) + runtime failure-mode suite + security suite + `python -m py_compile`.
3. Phase 4 → pivot unit tests (exact formula) + multi-hop mock-tool E2E (discover/corroborate/contradict/no-dup-run/stop).
4. Phase 5 → CLI+MCP smoke on temp state, live passive run vs `example.com`, full `pytest -q --tb=short`.

---

## Phase 2 — ERKG Memory, Provenance & WAL Persistence (DONE)

Implemented:
- `hub/models.py` — closed enums (`EntityType` 19 values, `EpistemicStatus` 6, `EdgeType`,
  `ExecutionStatus`, `ErrorCode`, `ExecutionMode`, `HypothesisType/Status`), `EvidenceArtifact`,
  `Entity`, `Claim`, `ClaimSource`, `Contradiction`, `ExecutionRecord`, `Hypothesis`,
  `Objective`, `ScopeConfig`, `BudgetConfig`, `PivotWeights`, `InvestigationConfig/State`,
  `IterationRecord`, `ToolCapability`, `PivotCandidate`, `ToolRunResult`, `ReflectionPacket`.
- `hub/erkg/resolution.py` — canonicalization for all types (email/IDNA, domain www+IDNA,
  subdomain classification incl. `co.uk` suffixes, URL tracking-param stripping, phone E.164-ish,
  IPv6 compression, ASN, repo/social-profile parsing, case-preserving crypto), deterministic
  entity ids, alias index keys, derivation (subdomain→parent, email→mail domain,
  profile URL→username, GitHub URL→repository).
- `hub/erkg/confidence.py` — deterministic rules: 1 source = `min(0.65, 0.10+0.60*rel)`;
  2+ independent tools = `0.85 + 0.05*(n-2) + 0.15*(avg_rel-0.5)`; CONFIRMED needs ≥2 direct
  sources and ≥0.90; contradiction = 0.30 `CONTRADICTED`.
- `hub/erkg/store.py` — SQLite WAL (`journal_mode=wal`, `synchronous=1`, `busy_timeout=5000`),
  tables investigations/entities/entity_aliases/artifacts/claims/claim_artifacts/contradictions/
  execution_ledger/hypotheses/iterations, DB-level status CHECK constraint, immutable artifacts,
  functional-predicate contradiction detection, RLock + `BEGIN IMMEDIATE` transactions.
- `hub/erkg/graph.py` — in-memory read model: BFS hop distances from seed, neighbors,
  local neighborhood, `shares_corroborated_identifier`.
- `hub/erkg/ingestion.py` — Normalize stage: evidence-backed `IDENTIFIED_AS` +
  `HAS_ATTRIBUTE:*` claims, relation edges, derived nodes, warning isolation per candidate.
- Tests: `tests/test_resolution.py` (33), `tests/test_confidence.py` (19), `tests/test_erkg.py` (47),
  `tests/test_ingestion.py` (11) → **110 passed**, including WAL pragma assertions,
  crash-rollback + reopen resume, 6-thread concurrent-writer stress, contradiction math.

## Phase 3 — Hardened Tool Runtime, Registry & Deterministic Parsers (DONE)

Implemented:
- `hub/tools/base.py` — strict `ParseOutput`/`EntityCandidate`/`RelationCandidate` contract,
  legacy `list[dict]` adapter, `infer_value_type`, deterministic parser loading.
- `hub/tools/capabilities.py` — 17 Pydantic `ToolCapability` manifests (14 binaries + 3
  python-native builtins), execution modes (`PASSIVE`/`ACTIVE_RECON`/`INTRUSIVE_BLOCKED`),
  parameter specs, timeouts, rate limits, reliability + prior yield, `shutil.which` health checks,
  auto-generated LLM tool schemas, MCP tool definitions and CLI capability table.
- `hub/tools/parsers/*` — **17 deterministic parsers** returning `ParseOutput` with evidence
  snippets + relations; fixture-driven tests (14 legacy parsers: `tests/test_parsers.py` 50 tests).
- `hub/tools/runtime.py` — async `create_subprocess_exec` (no shell), scrubbed env allowlist,
  isolated scratch dir, timeout + process-tree kill (POSIX killpg / Windows taskkill /T /F),
  global + heavy-local semaphores, per-tool token buckets, error classification
  (`MISSING_BINARY`, `TIMEOUT`, `NONZERO_EXIT`, `SPAWN_ERROR`, `RATE_LIMITED`, `SCOPE_BLOCKED`, ...).
- `hub/tools/builtin/{dns_lookup,http_headers,tls_cert}.py` + parsers — Python-native passive
  collectors (stdlib socket/ssl + httpx), SSRF-guarded.
- `hub/security/policy.py` — code-enforced pre-spawn gate (intrusive block, authorization gate,
  active-recon scope, allow/deny domain+entity lists, private/loopback/metadata IP block,
  DNS-resolving `assert_safe_host`).
- `hub/security/quarantine.py` — ANSI/control stripping, tag-escape neutralization,
  `<untrusted_osint_data>` wrapper, `SECURITY_SYSTEM_PROMPT`, recursive `sanitize_struct`,
  injection-pattern detection.
- Tests: parser fixtures 50, runtime/security/builtin **93 passed** (proves missing-binary
  no-spawn, timeout tree kill, env scrub, semaphore peak bound, token spacing, scope matrix,
  injection wrapper, live-safe collector fixtures).

## Phase 4 — Hypothesis & Pivot Scoring Engine (DONE)

Implemented:
- `hub/investigation/hypotheses.py` — 5 explicit hypothesis types (CORROBORATION, RESOLUTION,
  EXPANSION, IDENTITY_LINK, VERIFICATION), deterministic generation from lead claims,
  contradictions, seed entities, email↔username links; dedupe guard; post-run correlation
  (SUPPORTED/REFUTED) and stale marking.
- `hub/investigation/pivot.py` — exact spec formula
  `Score = w1*EIG + w2*CorroborationValue - w3*HopPenalty - w4*ExecutionCost`;
  hop>2 penalty (0.5+0.25/hop) with corroborated-identifier exemption ×0.2; open-hypothesis
  corroboration boost 1.0; ledger-key exclusion; deterministic diversified top-k.
- `hub/investigation/stopping.py` — budgets → objectives → pivot-threshold ordered hard stops.
- `hub/investigation/reflection.py` — quarantine-safe LLM packet (normalized delta + bounded
  neighborhood + open hypotheses + next pivots + wrapped external snippets) and sanitized
  response applicator.
- `hub/investigation/engine.py` — Plan→Execute→Normalize→Correlate→Score→Reflect loop;
  transactional iteration commit (artifact+claims+ledger+hypotheses+counters+record);
  deterministic seeding, scope derivation, objectives, resume, preview/step/investigate.
- Tests: `tests/test_pivot.py` (17), `tests/test_hypotheses.py` (11), `tests/test_stopping.py` (12),
  `tests/test_engine.py` (15 e2e with mock tools: discovery, cross-tool corroboration,
  contradiction, zero duplicate runs across resume, budgets, wall-clock, parse failure,
  intrusive/authorization exclusion, injection quarantine) → all green.
- **Full suite checkpoint: `369 passed in 6.25s`** (includes legacy suites still present).

## Phase 5 — MCP Server, CLI, Live Safe Smoke Test & Docs (DONE)

Implemented:
- `hub/reporting.py` — evidence-cited dossier: every claim line carries
  `**STATUS** (confidence, sources) [artifact_id(s)]`; sections: Executive Summary,
  Findings by entity type, Relationship Map, Contradictions (both values + citations),
  Collection Gaps / Dead Ends / Unverified Hypotheses, Provenance Appendix,
  Method & Epistemic Model. Deterministic Markdown + full JSON dossier; snippets all
  pass through the injection quarantine before rendering.
- `hub/service.py` — single implementation of the five operations, shared by both
  transports: `investigate`, `step`, `graph` (7 views), `tools`, `report` (+ `status`,
  `list`, legacy create). CLI↔MCP parity by construction.
- `hub/cli.py` — `python -m hub.cli` with the five spec operations + status/list;
  human and `--json` output; UTF-8-safe on Windows; clean non-zero exits on errors.
- `hub/mcp_server.py` — rewritten FastMCP **stdio** server (cross-platform; v1 used a
  POSIX Unix socket) exposing `investigate`, `step`, `status`, `graph`, `tools`,
  `report`. Verified with a real JSON-RPC handshake.
- `hub/orchestrate.py` — rewritten cross-platform legacy v1 shim
  (`--init/--step/--status/--report`, legacy `act_NNN` → `piv_…` mapping, no fcntl).
- Removed superseded v1 modules/tests: `hub/registry.py`, `hub/graph/`, `hub/planner/`,
  `hub/executor/`, `tests/test_{graph,candidates,evaluate}.py`. Kept `hub/cooking.py`
  (intake/permutations) and its tests.
- Docs: new `README.md` (architecture diagram, install, quickstart, MCP config,
  epistemic model, pivot formula, 17-tool matrix, security model, limitations),
  rewritten `docs/MCP_USAGE.md`, rewritten `skills/ai-os-orchestrator/SKILL.md` (v3
  agent policy), new project `AGENTS.md`, `pyproject.toml` + updated
  `requirements.txt`. `HANDOFF_AUDIT.md`/`PROJECT_BRAIN.md` marked historical.
- Safety hardening decisions this phase:
  * **Passive-first default** — `ACTIVE_RECON` capabilities are excluded from the
    pivot pool unless explicitly enabled (`--allow-active-recon` / MCP
    `allow_active_recon=True` / `scope.allow_active_recon`).
  * **Explicit allowlist is a hard boundary** — out-of-scope seeds are rejected
    before investigation start; allowlists are never widened by seeds.
  * **Resolved-IP scope expansion** — public IPs of allowlisted domains (from
    evidence-backed `RESOLVES_TO` claims) are added to `scope.allow_ips`; private /
    loopback / metadata IPs never are.
  * **amass invocation verified on host** (v4.2.0): fixed flags to
    `amass enum -passive -d <domain> -timeout 2`; v4 emits OAM graph text, so the
    parser now deterministically parses `FQDN/IPAddress/ASN/RIROrganization` triples
    (`tests/test_amass_oam.py`). Passive enum for example.com took ~128 s.

### Verification evidence (this host, Windows 11, Python 3.14.3)

- **Deterministic suite:** `371 passed, 1 skipped in 18.86s`
  (`python -m pytest -q --tb=short`; skip = opt-in live network test).
- **Live passive smoke:** `AI_OSINT_HUB_LIVE=1 pytest tests/test_live_smoke.py` →
  `1 passed in 0.75s` (builtin DNS/HTTP/TLS only, `example.com`, explicit allowlist).
- **Live CLI end-to-end:** `python -m hub.cli investigate example.com --max-iterations 2
  --max-tool-calls 2 --allow-domain example.com --report md --out … --json`:
  - ledger: `dns_lookup SUCCESS (17 ms)`, `tls_cert SUCCESS (41 ms)`;
  - 3 immutable artifacts, 4 entities (domain, 2×ip, organization), 8 claims
    (1 CONFIRMED, 7 SINGLE_SOURCE_LEAD), 0 contradictions;
  - dossier 4,812 bytes with `[art_…]` citations and all required sections.
- **Scope gate (live CLI):** investigating `example.org` with
  `--allow-domain example.com` → clean `{"status":"error", "errors":["seed target is
  outside the explicitly configured scope allowlist …"]}` (no collection started).
- **MCP stdio protocol:** real `initialize` + `notifications/initialized` +
  `tools/list` handshake → `AI OSINT Hub` serverInfo, six tools:
  `graph, investigate, report, status, step, tools`.
- **Legacy shim:** `import hub.orchestrate` works on Windows (v1 `fcntl` regression
  covered by test); `--init/--status/--report` JSON contracts verified.
- **Tool matrix:** `python -m hub.cli tools` → 6/17 available on this host
  (`amass`, `gobuster`, `nmap` + builtin `dns_lookup`, `http_headers`, `tls_cert`);
  the 11 missing binaries are reported MISSING, never mocked.
- **Py parser coverage:** 17/17 deterministic parsers fixture-tested
  (14 legacy + 3 builtin collectors); plus amass OAM-format tests.

## Toolchain Provisioning Phase — 17/17 AVAILABLE (2026-11-14, new directive)

**Goal:** eliminate every `❌ missing` row — all 17 capabilities installed, executable,
smoke-verified, and resolvable through managed bin dirs + WSL2 fallback.

### Acceptance evidence (this host)

1. **`python -m hub.cli tools` → `✅ 17/17 AVAILABLE`** with zero missing rows
   (per-tool resolver shown: managed-venv / managed-home / path / wsl / builtin).
2. **`python -m hub.cli doctor --provision` → `17/17 tools AVAILABLE, 17/17 healthy
   (smoke-checked in 14.92s)`**; every tool ran a real `--version`/`--help`
   subprocess (including WSL-bridged whatweb/hashcat/hydra). Re-running is
   idempotent: actions only say `already-available`.
3. **Deterministic suite:** `414 passed, 6 skipped in 30.40s`
   (`python -m pytest -q --tb=short`; skips are the two opt-in live suites).
4. **Live toolchain suite:** `AI_OSINT_HUB_LIVE=1 pytest tests/test_toolchain_live.py`
   → `5 passed in 100.51s` (doctor 17/17 + live holehe, whatweb, phoneinfoga,
   sherlock executions through the hardened runtime).
5. **Live engine investigations** (real network, benign/reserved targets):
   - username `torvalds` → **sherlock SUCCESS** (71,708 ms) · dossier 51,237 B
   - email `test@example.com` → **holehe SUCCESS** (11,835 ms) · dossier 17,691 B
   - phone `+14155552671` → **phoneinfoga SUCCESS** (70 ms) · dossier 3,486 B
   - domain `tesla.com` → **theHarvester SUCCESS** (9,504 ms) · 200 entities /
     401 claims · dossier 24,528 B
   - domain `example.com` forced pivot → **whatweb SUCCESS via WSL bridge**
     (8,652 ms) · 3 entities / 8 new claims · dossier 4,456 B with `[art_…]` citations
   - All five previously-missing passive tools thus executed live inside real
     engine investigations (ledger `SUCCESS`, evidence-backed dossiers).

### Architecture implemented

- `hub/tools/locator.py` — single resolution chain:
  1. managed launcher descriptors `~/.ai_osint_hub/bin/<tool>.launcher.json`
     (shell-free `python -m hub.toolchain.wrappers.<tool>`);
  2. managed native executables `~/.ai_osint_hub/bin` + repo `.venv*/Scripts`
     (auto-discovered, prepended to child PATH; no shell/PATH restart needed);
  3. host PATH;
  4. **WSL2 bridge** — `wsl.exe -d <distro> --exec <tool>` (shell-free; `/usr/bin/which`
     probes), results disk-cached at `~/.ai_osint_hub/toolchain_cache.json`
     (TTL 900 s) to avoid cold-start cost across CLI/MCP processes;
  5. packaged python wrapper fallback (real httpx implementations, never mock data).
  Batch/PowerShell launchers are rejected by the hardened runtime.
- `hub/toolchain/doctor.py` — per-tool resolution + real smoke subprocess, emoji
  table, JSON result; smoke tolerates non-zero help exits (e.g. hydra `-h` → 255)
  but rejects silent failures/tracebacks.
- `hub/toolchain/provision.py` — idempotent `doctor --provision`: creates managed
  dirs, installs python CLIs into the managed venvs (uv → pip fallback), downloads
  the official phoneinfoga release, apt-installs whatweb/hashcat/hydra inside WSL,
  and installs shell-free wrapper launchers only as a last resort.
- `hub/tools/runtime.py` — every binary spawn resolves through the locator
  (`resolved.command(argv[1:])`), merges trusted manifest env, enriches child PATH;
  policy gates unchanged and still run before spawning.
- `InvocationSpec.env` + `capabilities.tool_home()/invocation_env()` — per-tool
  writable config home (`<repo>/.toolhome/<tool>`); required because managed venv
  interpreters are sandbox-confined to the workspace (theHarvester hardcodes
  `~/.local/share/theHarvester` + `~/.theHarvester`).
- `HealthStatus.resolver` + `tools`/`doctor`/MCP doctor outputs expose the resolver.
- New CLI `python -m hub.cli doctor [--provision] [--json]`; new MCP tool
  `doctor(provision=False)`.

### Provisioned inventory

| Tool | Version/CLI | Provisioned where | Resolver |
|---|---|---|---|
| holehe | 1.61 | repo `.venv` (Python 3.11) | managed-venv |
| maigret | 0.6.6 | repo `.venv` | managed-venv |
| h8mail | 2.5.6 | repo `.venv` | managed-venv |
| sherlock | 0.16.2 | repo `.venv` | managed-venv |
| ghunt | 2.3.4 | repo `.venv` | managed-venv |
| snscrape | 0.7.0.20230622 | repo `.venv` | managed-venv |
| theHarvester | 4.11.1 | repo `.venv314` (Python 3.14; upstream needs ≥3.12) | managed-venv |
| phoneinfoga | 2.11.0 | `~/.ai_osint_hub/bin/phoneinfoga.exe` (official release) | managed-home |
| whatweb | 0.6.4 | WSL Ubuntu 26.04 apt | wsl |
| hashcat | 7.1.2 | WSL Ubuntu apt | wsl |
| hydra | 9.6 | WSL Ubuntu apt; stays `INTRUSIVE_BLOCKED` | wsl |
| nmap / amass / gobuster | host binaries | host PATH | path |
| dns_lookup / http_headers / tls_cert | python-native | repo code | builtin |

### Integration fixes discovered by live runs

- whatweb CLI: v0.6.4 rejects `--no-color`; manifest now uses `--color=never`.
- theHarvester v4.11.1: upstream CLI has no `-e` email param (email removed from the
  manifest/accepted types); invocation fixed to `-d <domain> -b crtsh -q`; its
  config/state redirected to a writable tool home; live run parses 200+ crtsh
  subdomains correctly.
- Parsers validated against real stdout (not just fixtures): holehe 122 entities /
  12 edges, sherlock 174 / 87, theHarvester 211 / 211, phoneinfoga phone+location
  (`LOCATED_IN`), whatweb URL+`HTTPServer[cloudflare]` services. whatweb parser now
  skips non-technology `Allow[...]`.
- Intake now extracts E.164-ish phone numbers as seeds (so phoneinfoga is reachable
  from free-form intel); dates are rejected as phones.
- ghunt needs `PYTHONIOENCODING=utf-8` on Windows (rich banner); runtime env
  allowlist forwards it.
- `tests/test_legacy_shim.py` updated for the now-complete toolchain.

### Residual notes

- ghunt health/smoke pass, but real scans need authenticated Google cookies
  (`ghunt login`); empty/error results are real collection outcomes.
- h8mail needs breach indexes/API configuration for hits; the executable itself is
  provisioned and verified.
- maigret `--version` works; a live text-mode probe exited 1 under `--top-sites`
  (CLI/config quirk) — toolchain health is unaffected; live demo list used the
  other tools.
- hydra is health-checked but never spawned unless `allow_intrusive` is explicitly
  enabled; hashcat remains authorization-gated.
- Managed layouts are gitignored (`.venv*`, `.toolhome/`, `.tmp/`);
  `doctor --provision` recreates them on a fresh host.

## Phases 7–9 — Native Expansion, Multi-Clue Intake, Web Workbench (2026-11-15)

### Phase 7 — maigret fix + 7 python-native passive collectors (24/24)

- **maigret root cause:** live runs failed because (a) maigret hardcodes
  `~/.maigret` (sandboxed managed-venv python cannot write the user home) and
  (b) the runtime's temp cwd is outside the workspace, so maigret's default
  `reports/` write hit `PermissionError`. Fixed with `USERPROFILE`/`HOME`
  redirect to `{tool_home}` **and** `--folderoutput {tool_home}/reports`;
  `capabilities.build_argv` now expands trusted writable-path placeholders in
  flags too (and creates path-flag folders). Verified live: maigret
  `torvalds --top-sites 50 --no-color --no-progressbar --no-autoupdate` →
  `LedgerStatus.SUCCESS`, 6 accounts, ~6.6 KB output.
- **New builtin collectors + parsers** (real httpx public queries, no keys,
  no cookies, no Tor daemon; SSRF-guarded via `hub.security.policy` /
  `builtin/_http.fetch_safe`; bounded outputs; 404/no-data = valid EMPTY):
  `photon_crawler` (root + robots.txt + sitemap.xml → links/emails/subdomains/
  social/JS endpoints/buckets), `github_osint` (profile/repos/events +
  commit-author emails + email search), `gravatar_lookup` (md5+sha256, JSON
  profile, linked accounts), `pgp_keyserver` (keys.openpgp.org → ubuntu HKP
  UID index; no key material imported), `rdap_lookup` (rdap.org JSON,
  registrar/contacts/nameservers/events), `wayback_cdx` (CDX collapsed
  200-filtered URLs + subdomains), `darkweb_ahmia` (clearnet .onion index;
  homepage anti-bot token dance).
- `python -m hub.cli tools` → **`✅ 24/24 AVAILABLE`**; `python -m hub.cli
  doctor` → **`24/24 tools AVAILABLE, 24/24 healthy (smoke-checked in ~20 s)`**.
  Live native-collector probes: rdap 4 entities/3 relations, gravatar 6/3,
  github email-search 26/19, photon `python.org` 125 entities, wayback live
  rows, theHarvester crtsh live.

### Phase 8 — unstructured multi-clue intake (`hub/intake.py`)

- Extracts all seed types from a messy paragraph and/or structured fields:
  `PERSON, USERNAME, EMAIL, DOMAIN, SUBDOMAIN, IP, URL, PHONE, ORGANIZATION,
  LOCATION` with deterministic cue regexes, IP/phone/URL/domain validation,
  dedupe + per-type bounds, and a fallback username anchor.
- Every clue is ingested with **`USER_PROVIDED_SEED` provenance** (entity
  metadata + `HAS_ATTRIBUTE:provenance` claim + seed artifact), and
  `_link_seed_entities` links every clue to the primary person (or first seed)
  with typed predicates (`HAS_USERNAME`, `HAS_EMAIL`, `OWNS`, `LOCATED_IN`,
  `ASSOCIATED_WITH`) so corroboration/hop-distance work across user clues.
- Bounded deterministic permutations: ≤20 usernames / ≤10 emails, all
  `HYPOTHESIS` confidence ≤ 0.35, linked to the primary person; exposed through
  `service.investigate/create`, CLI (`--name/--username/--email/--domain/
  --phone/--url/--ip/--org/--location`), MCP and the Web API.
- Store invariant fix: planner hypothesis claims never enter the contradiction
  machinery (`upsert_claim` conflict check requires an artifact;
  `_mark_contradiction` skips artifact-less claims), so no invalid
  CONTRADICTED-without-evidence claims can be created.

### Phase 9 — FastAPI Web Workbench (`hub/web.py`) + HTML dossiers

- `python -m hub.cli serve --host 127.0.0.1 --port 8000`: FastAPI app factory
  (`create_app(service=None)`, module `app`, lazy uvicorn) with embedded
  dark-mode SPA (Tailwind CDN + offline CSS, no Node build): multi-clue intake
  drawer, Quick/Standard/Deep budgets, scope allowlist, interactive SVG ERKG
  graph (click node/edge → evidence snippet + SHA-256 + epistemic badge),
  Graph/Telemetry/Dossier tabs, live event log, hypotheses/contradictions,
  “Run Next Pivot”, dossier viewer and `.md`/`.json`/`.html` downloads.
- Endpoints: `GET /`; `GET /api/tools`; `POST /api/doctor`; `POST|GET
  /api/investigations`; `GET /api/investigations/{id}` (full state + graph +
  artifact index); `GET /{id}/stream` (SSE snapshot/iteration/ledger/
  graph_delta/done, 0.4 s poll, keepalives, terminal/timeout stop);
  `POST /{id}/step`; `GET /{id}/report?format=md|json|html`.
  Background runs: `service.create` + `asyncio.to_thread(service.resume)`.
- `reporting.render_html`: standalone print-ready HTML dossier (dark theme +
  `@media print`, all untrusted OSINT HTML-escaped). CLI/MCP/Web support
  `format=html`.

### Verification evidence (this host)

- `python -m hub.cli tools` → `✅ 24/24 AVAILABLE`.
- `python -m hub.cli doctor` → `24/24 tools AVAILABLE, 24/24 healthy`
  (per-tool real `--version`/`--help` or builtin importability).
- Deterministic suite: **`491 passed, 12 skipped in 43.31s`** (12 skips are the
  opt-in live suites). New deterministic tests: 49 native-collector tests,
  14 intake/permutation tests, 9 FastAPI workbench tests, HTML dossier +
  structured-intake CLI tests.
- Live acceptance (`AI_OSINT_HUB_LIVE=1`): **`12 passed in 186.40s`** covering
  maigret, github_osint, rdap_lookup, wayback_cdx, photon_crawler,
  theHarvester-crtsh, holehe, whatweb, phoneinfoga, sherlock, doctor 24/24 and
  the passive-only live smoke.
- Live Web Workbench (real uvicorn on 127.0.0.1:8899, real engine):
  UI `200` 27,857 B; `/api/tools` total 24; `POST /api/doctor` 24/24 healthy;
  background investigation started → SSE `snapshot`+`done`; state 152
  entities/310 claims/2 artifacts; Markdown/JSON/HTML dossiers exported
  (25,967 B / 474,165 B / 58,029 B); investigation list populated.
- `python -m hub.cli serve --help` verified; `tests/test_web_api.py` 9/9 green
  (UI markers, tools, doctor, wait/background+SSE, state, step, md/json/html,
  404s).

### Known limitations / notes

- Ahmia may rate-limit or change its anti-bot token → surfaces as
  `RATE_LIMITED`/`SPAWN_ERROR` collection failure (honest, never mocked).
- GitHub unauthenticated API can transiently return secondary-rate-limit 403;
  classified `RATE_LIMITED`; a live run may need a retry.
- keys.openpgp.org only supports e-mail/keyid search (name search → fallback);
  ubuntu keyserver may return `pub:` without `uid:` (fingerprint-only).
- Wayback CDX can 503/timeout under load; handled as collection failure.
- maigret prints bot-protection warnings on some sites but returns SUCCESS with
  real accounts; it is bounded to top-50 sites.
- All live phases wrote state under `.tmp/...` (gitignored); managed toolchain
  layouts remain gitignored and reproducible via `doctor --provision`.

## Phase 10 — 5-Provider API Integration, Credential Vault & Web API Keys UI (2026-11-15)

### Delivered

- **`hub/credentials.py`** — secure provider vault at
  `~/.ai_osint_hub/credentials.json` (outside the repo; mode 0600 where
  supported), env-var override precedence, masked-preview status, and
  `save_provider()` / `configure_from_mapping()` updates. Providers:
  `GITHUB_TOKEN`, `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`,
  `CENSYS_API_ID`+`CENSYS_API_SECRET` or `CENSYS_TOKEN` PAT,
  `HUNTER_API_KEY`. **All five providers are CONFIGURED in the local vault**
  (only masked previews are ever printed/returned).
- **`hub/security/redaction.py`** — registered-secret filter replacing raw values
  with `[REDACTED:<PROVIDER>]`; wired into `ToolRuntime.finish()` so stdout,
  stderr, error messages and params are redacted before ledger/artifact/report
  storage. Verified by a test collector that intentionally echoes a secret:
  SQLite/runtime never sees it.
- **`.toolhome/theharvester/.theHarvester/api-keys.yaml` auto-sync** on
  load/update (gitignored, sandboxed-HOME path), preserving unrelated provider
  keys and mapping virustotal/shodan/censys/hunter/github fields.
- **4 new native API collectors + parsers** (`virustotal_lookup`,
  `shodan_lookup`, `censys_lookup`, `hunter_lookup`) + **github_osint token
  auth**. All are SSRF-safe fixed-host httpx calls, bounded, key-scrubbing,
  missing-key → `AUTHORIZATION_REQUIRED`, and registered as tools 25–28.
- **Auth-aware health/pivot gating** — `HealthStatus.auth_status/auth_detail`
  and `ToolCapability.auth_provider`; `tools`/`doctor` show an Auth column.
  Pivot planner and runtime skip `MISSING_KEY`/`PARTIAL`/
  `OPTIONAL_UNCONFIGURED` tools instead of wasting budget. ghunt/h8mail are
  `OPTIONAL_UNCONFIGURED` (skipped cleanly) until a local session/config exists.
- **Web UI API Keys drawer** — `GET/POST /api/credentials` (masked only),
  modal with password-masked inputs, green/amber Configured/Not Set badges,
  “Save & Sync Keys”; saving syncs theHarvester YAML and refreshes auth statuses.
- **CLI parity** — `python -m hub.cli auth status` and
  `auth set <provider> <value>` (`--censys-secret`, `--censys-token`).

### Verification evidence

- `python -m hub.cli tools` → **`✅ 28/28 AVAILABLE · auth-ready 26/28`**
  (ghunt/h8mail optional-unconfigured only; all 5 API tools CONFIGURED,
  github_osint CONFIGURED via token).
- `python -m hub.cli doctor` → **`28/28 tools AVAILABLE, 28/28 healthy
  (smoke-checked in 12.73s); credentials ready for 26/28 tools`**.
- Deterministic suite: **`586 passed, 18 skipped in 37.95s`**. New Phase-10
  tests: `tests/test_credentials_and_apis.py` (28 tests: vault, env override,
  masked status, redaction, Harvester YAML sync, all 4 collectors/parsers,
  `/api/credentials`, UI modal markers, CLI auth) and
  `tests/test_api_collectors_phase10.py` (67 mocked-transport tests incl.
  GitHub Bearer/keyless, Censys Platform API, error mapping).
- Live API smoke (real vault keys, benign targets; no secrets printed):
  - github_osint `torvalds` → SUCCESS, 17 entities / 15 relations, ~2.0 s,
    `auth_status CONFIGURED` (5000 req/h);
  - virustotal_lookup `example.com` → SUCCESS, 83 entities / 82 relations ~5.2 s;
  - shodan_lookup `8.8.8.8` → SUCCESS, 10 entities / 7 relations ~0.3 s;
  - censys_lookup `1.1.1.1` → SUCCESS, 36 entities / 33 relations ~1.5 s
    (Censys Platform PAT);
  - hunter_lookup `example.com` → `RATE_LIMITED`: Hunter account status is
    valid/`CONFIGURED` but the free account is provider-restricted (`429
    restricted_account`, reset 2026-12-14). Classified honestly; never mocked.
- Live suites (`AI_OSINT_HUB_LIVE=1`): API-key smoke **6 passed in 10.17s**
  (credentials configured + GitHub/VT/Shodan/Censys live executions); toolchain/
  native live suite **12 passed in 162.15s** (28/28 doctor plus real maigret and
  collector executions).
- Web API keys routes verified with FastAPI `TestClient` (masked GET, POST saves
  all providers + syncs YAML, no raw secret in responses); UI HTML contains
  `API Keys`, `api-keys-modal`, all key inputs, badges and Save & Sync button.
- Secret audit: no API key material present in any tracked/working-tree file;
  vault lives outside the repo and theHarvester YAML is ignored.

### Limitations / notes

- **Censys Legacy Search API was decommissioned (Sept 30 2026)**; the provided
  Censys credential is a Platform PAT, so `censys_lookup` uses
  `api.platform.censys.io/v3/global/asset/host/{ip}` with Bearer auth. Platform
  global search requires an org ID (403 for free users), so domain lookups
  resolve A records then fetch host assets (cert/DNS names filtered to
  subdomains). Legacy id/secret-only config is reported as decommissioned.
- Hunter.io free account is currently restricted by Hunter (429
  `restricted_account`); the key is valid and the tool is CONFIGURED, but live
  searches are rate-limited until the provider lifts the restriction.
- ghunt/h8mail stay AVAILABLE but auth-gated (`OPTIONAL_UNCONFIGURED`) so pivots
  never run them unauthenticated.
- `.toolhome/.../api-keys.yaml` intentionally contains raw keys for theHarvester
  but is gitignored; the credential vault itself is outside the repository.

## Phase 11 — Parser Precision, Seed-First Pivoting, Transliteration Intake & Graph UX (2026-11-15)

### Delivered

- **`holehe` parser precision (`hub/tools/parsers/holehe.py`):** only `[+]` lines
  produce `Service` nodes and `email REGISTERED_ON service` edges. `[-]`/`[x]`
  lines are ignored entirely. Banner/footer credits (`@palenath`, `megadose`,
  BTC address, legend, timing) and profile URLs outside a positive context are
  skipped. Registration is **relation-only** — no `HAS_ATTRIBUTE:registered`
  attributes/metadata on `Service` entities (the ingestor copies relation
  metadata as object attributes, so holehe relation metadata is intentionally
  empty). This eliminates fake cross-email contradictions.
- **Seed-first pivot scoring (`hub/investigation/pivot.py`, engine):**
  `USER_PROVIDED_SEED` entities (metadata provenance) receive a `+0.35` seed
  expansion bonus, plus `+0.10` for an uncovered seed type and `+0.06` for a
  not-yet-used seed-wave tool; `-0.08` for tool saturation. Guessed
  `USER_DERIVED_HYPOTHESIS` permutations are tier-sorted after all user seeds
  while any primary seed type (username/email/phone/domain/ip/url) is uncovered,
  and their corroboration value is capped at **0.20** until the seed wave is
  complete. User threshold semantics remain absolute. Seed emails no longer
  auto-populate `scope.allow_domains`; only explicit allowlists or genuine
  DOMAIN/SUBDOMAIN seeds do.
- **Precision intake (`hub/intake.py`):** Unicode-safe person/organization cue
  parsing (previously `Taşkin` was truncated to `Ba`); diacritic
  transliteration with digraph + ASCII variants (`Taşkin` → `tashkin`/`taskin`,
  `Əliyev` → `eliyev`/`aliyev`, never `takin`); expanded stopword set rejects
  prose fragments (`elvin_in`, `in_elvin`); hypotheses capped at **6 usernames /
  4 first+surname emails**, never single-first-name provider emails
  (`elvin@gmail.com`); known surname tokens mined from seed email local-parts
  (`elvin.s.tashkin.std` → `tashkin`); structured orgs/locations split on
  commas/semicolons/newlines, while usernames/emails/domains/phones/urls/ips split
  on whitespace too. Domain clues that appear only inside an email address are no
  longer extracted as separate domain seeds.
- **Web Workbench UX (`hub/web.py`):** multi-ring concentric (subject center,
  inner identity ring, outer discovery rings) deterministic force-relaxed graph;
  mouse-wheel zoom, drag-to-pan, Zoom +/−/Reset, node search, clickable
  entity-type filter pills; clean empty intake defaults (no example.com /
  93.184.216.34 placeholders), Clear Form button and red error banner. SSE
  keepalive is 2 s; stream deadline = investigation `wall_clock_timeout_sec` +
  30 s; frontend settles the badge to **COMPLETED** and loads the dossier when
  terminal (including after a timeout/closure race).
- **Docs:** README Phase-11 data-quality/UX section, AGENTS invariants updated.

### Verification evidence

- `python -m pytest -q --tb=short` → **`606 passed, 18 skipped in 111.82s`**
  (skips are the opt-in live suites). New `tests/test_phase11_quality.py`:
  **18 passed** covering `[+]`-only holehe + banner stripping + zero fake
  contradictions, transliteration/stopwords/field splitting, seed-first pivot
  ordering/corroboration cap/cross-entity wave + engine provenance integration,
  and Web graph/SSE controls/defaults/timeout deadline.
- Existing `tests/test_parsers.py` holehe assertions updated to the corrected
  positive-only behavior; all other 28-tool, intake, engine, web and credential
  suites remain green.
- `python -m hub.cli tools` still reports **28/28 AVAILABLE**; no toolchain
  changes were needed.
- JavaScript syntax checked with `node --check` on the embedded workbench script
  (clean).

### Notes

- The live dossier `case_20261114_213949_3151` was produced by the pre-fix
  parser/planner; it is retained as an archival artifact. New investigations use
  the corrections above.
- Source-first tiering intentionally does not bypass an explicitly configured
  `min_pivot_threshold`; seed pivots are prioritized among admissible pivots.

## Phase 12 — Rate-Limit Breaker, Location Semantics, GitHub/Maigret Resilience & Graph De-clutter (2026-11-15)

### Delivered

- **Hierarchical `LOCATED_IN`:** removed from `FUNCTIONAL_PREDICATES`; a person
  located in both `baku` and `az` (or `"Baku, AZ"`) now stores complementary
  claims with zero contradictions. Intake expands structured/free-text
  city+2-letter country pairs to `["Baku, AZ", "Baku", "AZ"]`, so a
  phoneinfoga country hit (`LOCATED_IN -> az`) corroborates the seed claim
  (CORROBORATED/CONFIRMED) instead of tainting the subject.
- **In-run circuit breaker:** `hub/investigation/engine.py` inspects the
  execution ledger each iteration and excludes any tool that has already
  recorded `RATE_LIMITED`, `AUTHORIZATION_REQUIRED` or `MISSING_BINARY` from
  pivot generation/ranking in the same investigation (pivot scorer gained
  `blocked_tool_ids`). A rate-limited tool burns at most one call per run.
- **Institutional mail-domain seed wave:** non-freemail domains derived from
  email seeds (e.g. `example.edu.az`) become `EMAIL_DERIVED_DOMAIN` seed entities
  (also promoted onto ERKG DOMAIN/SUBDOMAIN classification nodes) so domain
  collectors join the seed wave. They are explicitly skipped by `_derive_scope`
  and never auto-lock scope. ERKG entity metadata merge was fixed so provenance
  survives email→domain derivation.
- **GitHub resilience:** standard `Accept`, `X-GitHub-Api-Version: 2022-11-28`
  and `User-Agent: ai-osint-hub` headers; authenticated primary 401/403 triggers
  one keyless retry; `/repos`, `/events/public` and `/search/commits` secondary
  failures are warnings only (never discard a good profile, never raise false
  `RATE_LIMITED`); `/users/{u}` 404 returns a clean EMPTY result (stdout empty,
  exit 0). Token never appears in output/errors.
- **maigret hardening:** manifest forces `PYTHONIOENCODING=utf-8`,
  `PYTHONUTF8=1`, `NO_COLOR=1` (fixes colorama cp1252 crash on non-Latin found
  IDs) and sets `tolerate_nonzero_with_stdout` so a completed scan with site
  warnings is SUCCESS/EMPTY, not `NONZERO_EXIT`.
- **Graph de-clutter:** graph payload flags HYPOTHESIS-derived nodes
  (`is_hypothesis`) and ships them hidden by default; toolbar gained
  **Show Hypotheses (N)** (OFF by default) and **Show Edge Labels** (OFF by
  default; labels only when toggled/selected), with larger inner/outer ring
  radii and stronger repulsion for separation.

### Verification evidence

- `python -m pytest -q --tb=short` → **`621 passed, 18 skipped in 102.40s`**
  (skips are opt-in live suites). New `tests/test_phase12_resilience.py`:
  **15 passed**, covering LOCATED_IN non-contradiction + phoneinfoga
  corroboration, circuit breaker integration/selection, institutional-domain
  promotion without scope locking, GitHub 404/403/422/auth-retry/header
  behavior, runtime nonzero-stdout tolerance, and Web graph hypothesis/label
  toggles.
- Live verification (`github_osint`, `maigret`; real vault):
  - `github_osint elv1ntsk` → SUCCESS EMPTY (404, exit 0, no error)
  - `github_osint 108.elv1n` → SUCCESS EMPTY (404, exit 0, no error)
  - `github_osint torvalds` → SUCCESS, 18 entities / 16 relations,
    `auth_status CONFIGURED` (zero false RATE_LIMITED)
  - `maigret elv1ntsk` → SUCCESS (clean EMPTY result, no NONZERO_EXIT)
  - `maigret 108.elv1n` → SUCCESS, 6,349 bytes stdout, 28 entities / 14
    relations (previously NONZERO_EXIT code 1)
- JS syntax checked with `node --check` on the embedded workbench script.
- `python -m hub.cli tools` remains 28/28 AVAILABLE; no toolchain changes.

### Notes

- Circuit breakers are per-investigation only; a new investigation may retry a
  previously limited tool. MAIGRET's textual report may contain no entities for
  sparse usernames (clean EMPTY) — that is a real collection outcome.
- HTTP secondary failures remain visible in stderr/collection-gap context, not
  silently mocked.

## Phase 13 — theHarvester Hygiene, Public Suffixes, Native snscrape & Hypothesis Hygiene (2026-11-15)

### Delivered

- **theHarvester banner/config filtering:** parser strips author credits
  (`Christian Martorella`, `cmartorella@edge-security.com`,
  `edge-security.com`), banner/legend lines, and config logs
  (`Read proxies.yaml…`, `api-keys.yaml`, `Sourcing from`, etc.) before any
  extraction; fallback broad extraction uses the cleaned text. Those identifiers
  are excluded unless the target is `edge-security.com`. The section parser and
  host-token path also reject config/code filenames.
- **Global file-extension guard:** `normalize_domain`, `split_hostname` and
  `derive_entity_drafts` reject `.yaml/.yml/.json/.xml/.txt/.md/.py/.exe/.dll/
  .conf/.ini/.cfg/.sqlite/.db/.log/.html/.htm/.js/.css/.png/.jpg/.svg/...`
  tokens, so `proxies.yaml` can never become a DOMAIN/SUBDOMAIN entity even in
  the broad fallback.
- **Multi-part public suffixes:** `split_hostname` now treats second-level
  `edu/ac/gov/org/com/net/co/mil/int.<any-2-letter-cc>` as public suffixes.
  `example.edu.az` is a **root DOMAIN** (no `domain:edu.az` parent);
  `mail.example.edu.az` is its subdomain. Email-derived domains are linked to the
  primary Person with **ASSOCIATED_WITH**, never `OWNS`; explicitly supplied
  `domains` still get `OWNS`. Email local-parts are no longer misinterpreted as
  free-text domain clues.
- **Native snscrape replacement:** removed the upstream CLI invocation (always
  exit 2) and added `hub/tools/builtin/snscrape.py`, a zero-auth async httpx
  probe across GitLab, Reddit, Keybase, HackerNews, Lichess, Chess.com, Dev.to,
  Mastodon and Medium. It emits JSONL matching the existing parser, returns
  exit 0 with a clean EMPTY result when nothing is found, and never
  NONZERO_EXIT. Provisioning no longer tries to pip-install snscrape.
- **Hypothesis hygiene:** `HypothesisGenerator` ignores internal bookkeeping
  claims (`HAS_ATTRIBUTE:clue_field`, `clue_source`, `provenance`, `role`,
  `seed_wave`, `derived_from_email`) and only creates CORROBORATION hypotheses
  for meaningful OSINT claims.
- **Sherlock soft-404 filtering:** known Sherlock v0.16 false-positive sites
  (`7cups`, `f3.cool`, `houzz`, `forums.envato.com`) are filtered from claimed
  services/profiles/relations.

### Verification evidence

- `python -m pytest -q --tb=short` → **`636 passed, 18 skipped in 61.03s`**
  (baseline 621 preserved + new suite). New
  `tests/test_phase13_hygiene.py`: **15 passed**, explicitly covering banner/
  config leaks, global file-extension rejection, multi-part suffix
  classification + ASSOCIATED_WITH vs OWNS, native snscrape JSONL/runtime
  behavior, internal-attribute hypothesis filtering, and Sherlock soft-404s.
- `python -m hub.cli tools` → **28/28 AVAILABLE · auth-ready 26/28**;
  `python -m hub.cli doctor` → **28/28 healthy in 8.96s** (snscrape now a
  builtin python-native tool).
- Live snscrape verification (`ToolRuntime`, real public endpoints):
  - `torvalds` → **SUCCESS**, exit 0, 640 bytes JSONL, 7 entities / 3 relations
  - `alice` → **SUCCESS**, exit 0, 1,181 bytes JSONL, 13 entities / 6 relations
  - no NONZERO_EXIT / no `exit code 2`.
- All existing theHarvester/parser/engine/web/credential suites remain green;
  `theHarvester` live crtsh integration unchanged.

### Notes

- theHarvester still prints its banner in raw artifacts (evidence provenance is
  preserved), but parsed entities/relations never include banner/config data.
- `example.edu.az` root-domain classification is public-suffix based, not a
  hard-coded host exception.
- snscrape platform endpoints may rate-limit; per-platform failures are warnings
  and the overall run remains a clean SUCCESS/EMPTY.

## Phase 14 — Complete Seed Coverage, Provider Cooldown & Default Budget Tuning (2026-11-15)

### Delivered

- **Per-seed productive coverage:** pivot scoring now treats a seed entity as
  covered only when its ledger contains a `SUCCESS` run; attempted seeds with
  only `EMPTY`/`ERROR` results receive an **Uncovered-Seed Rescue Bonus (+0.25)**
  on their next highest-prior tool. `uncovered_seed_types` is likewise based on
  successful coverage, so guessed/hypothesis pivots stay starved until real
  seed coverage exists.
- **Seed round-robin:** seed candidates are ordered one attempt per seed entity
  before any seed gets a second pivot (then by score/bonuses). This prevents six
  fast domain collectors from starving two username seeds; a simulated
  2-usernames + email + phone + domain investigation covers both usernames with
  github/sherlock/maigret and the domain with VirusTotal/DNS/TLS inside 10 calls.
- **Fast domain priority:** `dns_lookup`, `tls_cert`, `rdap_lookup`,
  `virustotal_lookup`, `photon_crawler` get a +0.25 fast-domain bonus (DNS/VT/TLS
  +0.12) so they rank at or above `theharvester` on domain seeds;
  sherlock/maigret retain higher prior yields than snscrape. Free-text intake now
  preserves dotted handles (`108.elv1n`) instead of splitting them into
  `108`/`elv1n`.
- **Cross-run provider cooldown:** new `hub/tools/cooldown.py` records a
  24-hour cooldown for `hunter_lookup`, `censys_lookup`, `shodan_lookup` and
  `virustotal_lookup` on `RATE_LIMITED` (e.g. Hunter HTTP 429
  `restricted_account`). Cache is persisted at
  `$AI_OSINT_HUB_HOME/rate_limit_cache.json`; `capabilities.available_tool_ids`
  and the pivot planner (engine + scorer blocked set) skip cooling tools.
  Credentials updates (`save_provider` / Web API Keys / `cli auth set`) and
  `reset_cache()` clear the file and memory.
- **Web UI defaults:** `InvestigateRequest.max_iterations` and the form default
  are now **16** (was 10); `max_tool_calls` remains 20. `Show Hypotheses` and
  `Show Edge Labels` render unchecked on load and `Clear` resets them to
  unchecked/false (plus graph re-render); default graph state remains hidden.

### Verification evidence

- `python -m pytest -q --tb=short` → **`649 passed, 18 skipped in 53.08s`**
  (baseline 636 preserved + new suite). New
  `tests/test_phase14_coverage.py`: **13 passed**, covering rescue bonus for
  attempted-empty users/domains, success clearing the bonus, fast-domain vs
  theHarvester ordering, sherlock/maigret vs snscrape, provider cooldown
  round-trip/expiry/credential reset, engine RATE_LIMITED marking, 10-call
  multi-seed simulation, Web 16/20 defaults, no `checked` checkboxes, and
  Clear-form toggle reset.
- `python -m hub.cli tools` → **28/28 AVAILABLE · auth-ready 26/28**.
- Multi-seed engine simulation (mock tools, real engine loop): first 10 pivots
  included both usernames (`github_osint`/`maigret`/`sherlock`), domain
  `virustotal_lookup`/`dns_lookup`/`tls_cert`, plus `holehe`/`gravatar_lookup`
  and `phoneinfoga`; stop reason `max_iterations` with all seed types covered.
- Regression suites `test_phase12`, `test_phase13`, `test_phase14`: 42 passed.

### Notes

- Cooldown is per provider tool and does not hide the tool from the 28/28
  inventory; only pivot planning is gated. Per-investigation circuit breaker
  still applies for all tools.
- A seed with no attempts yet is not "rescue"-flagged, but already carries the
  existing seed/uncovered-type bonuses; round-robin gives it a first pivot.
- `theHarvester` remains available and is scheduled after fast native collectors
  once the seed domain gets coverage.

## Phase 15 — Strict Handles, Maigret Target Filter, Role Semantics & Radial Graph (2026-11-15)

### Delivered

- **Strict free-text username extraction:** replaced the bare-token/ordinal
  heuristic with explicit indicators only — `@handle`, labeled cues
  (`username:`, `user:`, `handle:`, `nick:`, `nickname:`, `screen name:`,
  `alias:`, `aka`, `goes by`), `u/<handle>`, and known social profile URL paths.
  Bare prose tokens/ordinals (`2nd`, `18`, `c2`, `v2`, `sha256`, `http2`, …) are
  never promoted. Explicit cues can list several handles (`goes by a and b`,
  including dotted `108.elv1n`); a raw input that is exactly one bare handle
  remains a valid target. Structured `usernames` plus prose produces no false
  usernames.
- **maigret target filtering:** both JSON and text paths now compare URL paths /
  usernames to the queried target. Generic paths (`youtube/about`, login,
  signup, explore, channel, user(s), profile(s), status, settings, watch, help,
  …), collateral recursive names (`shame`, `humidify`, `about`) and malformed
  evidence are rejected; the URL path is authoritative and relations use the
  target handle. Existing alice fixture profiles remain correct.
- **Role semantics:** `hub/models.py` gained `NON_FUNCTIONAL_ATTRIBUTE_KEYS`
  and `is_functional_predicate()`; `HAS_ATTRIBUTE:role`,
  `clue_field`, `clue_source`, `provenance`, `seed_wave`,
  `derived_from_email` never mark claims CONTRADICTED. `store._is_functional`
  and `Claim.is_functional_conflict` use the helper; multi-role domains are
  stored as parallel SINGLE_SOURCE_LEAD/CORROBORATED claims. `registered` etc.
  stay functional.
- **Radial graph layout:** `layoutGraph` now anchors every node to a target
  `(ring radius, angle)` with `k_radial=0.085`, plus repulsion (32 cap) and
  edge springs (155 rest). Iterations never clamp x/y; a final circular,
  aspect-preserving fit scales all non-center coordinates by `maxRadius` into
  `fitRadius = min(width,height)/2 - 42`. 150-node simulation confirms nodes
  stay inside the circle and off the old rectangular walls/corners.
- **Transient fetch UX:** `isTransientNetworkError`/`transientError` detect
  `Failed to fetch`/`NetworkError`; `refreshState` retries silently (1.2 s) while
  a target is active, and data/status/graph/dossier successes call
  `clearError()`. `setStatus("running"/"COMPLETED")` clears the banner; genuine
  HTTP/application errors still surface.

### Verification evidence

- `python -m pytest -q --tb=short` → **`666 passed, 18 skipped in 41.83s`**
  (baseline 649 preserved + new suite). New
  `tests/test_phase15_precision.py`: **17 passed**, covering exact acceptance
  prose (zero `2nd`/`18`), explicit cue/`@`/`u/`/profile URL extraction,
  multi-handle cues, structured+prose, maigret generic/collateral filtering,
  multi-role no-contradiction (and functional `registered` still conflicting),
  150-node graph layout via Node, and transient-fetch/clear-message JS markers.
- `python -m hub.cli tools` remains **28/28 AVAILABLE**.
- Existing Phase 11-14 regression suites remain green (intake fallback test
  updated to the new strict-prose contract; standalone target test retained).

### Notes

- Graph algorithm is deterministic; `fitScale` only shrinks (never expands), so
  small graphs keep their ring spacing while large graphs fit a circle.
- Maigret with no target still rejects generic help/about paths.
- Transient retry is intentionally silent only for network-level failures; API
  validation/HTTP errors continue to display in `#ui-message`.

## Phase 16 — Full-Handle Maigret, Photon Assets, Empty Attributes & Resolved-IP Pivots (2026-11-15)

### Delivered

- **Maigret full-handle matching:** target forms are only the complete handle
  plus its punctuation-normalized equivalent (`108.elv1n` == `108_elv1n` ==
  `108-elv1n` == `108elv1n`). Dotted targets are never split into partial
  prefixes (`108`, `elv1n`). Root-only URLs (`https://discord.com`,
  `https://discord.com/`) are rejected; the generic blocklist now includes
  `contact`, `privacy`, `terms`, `feed`, `share`, `intent` alongside
  about/login/search/user/profile/settings/watch/help. URL path is authoritative.
  Acceptance output keeps only `calendly.com/108.elv1n` from the mixed batch.
- **Photon asset/page hygiene:** both collector and parser filter static
  theme/media/script/font URLs (`.css`, `.js`, `.mjs`, `.map`, `.svg`, `.png`,
  `.jpg/.JPG`, `.ico`, fonts, media, `.pdf`, `.zip`) and third-party CDN hosts
  (`code.jquery.com`, `cdnjs.cloudflare.com`, `fonts.googleapis.com`,
  `fonts.gstatic.com`, `cdn.jsdelivr.net`, `unpkg.com`, `bootstrapcdn.com`).
  Collector `urls` and parser `URL` entities are capped at **15 high-signal
  internal page URLs**; subdomains/emails/social profiles remain collected.
- **Role mailboxes:** `info/contact/admin/support/office/mail/hr/sales/press/help`
  local-parts are kept as `Email` entities linked to the domain, but
  `HypothesisGenerator` no longer creates `username:<role>` or
  “Is username 'info' linked to …?” identity-link hypotheses.
- **Empty attributes:** VirusTotal parser cleans `None`/blank values before
  EntityCandidate attributes; `ERKGIngestor` skips empty/whitespace strings.
  No `HAS_ATTRIBUTE:as_owner -> ""`, `asn`, `country`, `registrar` claims are
  created (non-empty values such as `reputation=0` and `keep="ok"` remain).
- **Resolved-IP infrastructure pivots:** a `RESOLVES_TO` claim from a root
  DOMAIN to an IP identifies primary infrastructure. `shodan_lookup`/`censys_lookup`
  on that IP and `rdap_lookup`/`http_headers` on the root DOMAIN receive
  **+0.22**, a top priority tier, and rationale
  “infrastructure corroboration (resolved primary IP)” — ahead of
  `darkweb_ahmia`, `pgp_keyserver`, `snscrape`, and institutional-email
  `github_osint`.
- **Provider cooldown TTL:** `RATE_LIMIT_COOLDOWN_SEC` is now **86,400s (24h)**
  so restricted API accounts stay cooled across sessions until credentials are
  updated or `reset_cache()` is called.

### Verification evidence

- `python -m pytest -q --tb=short` → **`676 passed, 18 skipped`**
  (baseline 666 preserved + new suite). New `tests/test_phase16_signal.py`:
  **10 passed**, covering the exact mixed maigret batch, root/generic rejection,
  punctuation equivalence, photon collector/parser asset filtering + 15-page
  cap, role-mailbox no-username hypothesis, VT/ingestor empty attribute removal,
  confirmed-IP Shodan/Censys ranking ahead of darkweb/pgp, and the 24h TTL.
- Existing photon/native-collector, parser, Phase 14/15 and full regression
  suites remain green.
- `python -m hub.cli tools` remains **28/28 AVAILABLE**.

### Notes

- The 15-page cap is per photon run; JavaScript endpoint URLs remain in raw
  payload/evidence but are not converted into URL entities.
- Infrastructure priority is applied at the pivot-ranking tier level, so the
  primary IP is scheduled immediately after the resolution edge appears, not
  after all seed low-yield expansion.
- Cooldown still gates pivot planning only; the tool stays in the 28/28
  inventory and clears on credential update.

## Phase 17 — Self-Test Fixes: Handle Guard, GitHub Email Pivot, Ahmia & Phone (2026-11-15)

### Delivered

- **Global USERNAME guard:** `resolution.normalize_username`/`is_valid_username`
  reject `@`, spaces, `/`, URLs and generic slugs (`search-by-username`, `about`,
  `user(s)`, `profil`, …); `derive_entity_drafts` drops invalid USERNAME drafts,
  and `EvidenceIngestor` reclassifies an e-mail-labelled USERNAME as EMAIL.
  Sherlock filters the expanded soft-404/root-only set and maigret advertises
  `--no-recursion`.
- **Intake precision:** a non-role e-mail local-part (e.g.
  `kamranmammadov01@example.com` → `kamranmammadov01`, `.std` stripped) is emitted as
  an `EMAIL_DERIVED_USERNAME` seed (confidence 0.64); the engine promotes it
  into `seed_entity_ids` with provenance/metadata and links
  `Person HAS_USERNAME`. Generic role mailboxes are excluded. Structured names
  suppress partial parsed Persons (`Ali` from `Aliyev`), and overlapping
  first/handle tokens no longer create doubled permutations
  (`kamran.kamranmammadov01`, `kamrankamranmammadov01`). AZ local phones normalize to
  E.164 `+994501234567`; `00…` becomes `+…`; pivot params also normalize phone
  entities before invoking phoneinfoga.
- **GitHub e-mail pivot:** `github_osint` on an e-mail now searches users by
  `in:email` **and** commits by `author-email:` (per_page 10), probes
  `/users/<local-part>`, harvests author/committer logins and
  `repository.full_name`, then hydrates `/users/<login>` and
  `/users/<login>/repos?per_page=30&sort=updated` in the same execution.
  Parser emits login + repositories (`OWNS`) and never e-mail-as-USERNAME.
- **Ahmia exact-match:** e-mail/username results are kept only when the full
  e-mail or distinctive local-part (≥5 chars) literally appears in title,
  snippet or URL; gmail.com-only shop/onion results are dropped. Domain searches
  retain the existing behavior.
- **Sherlock/maigret hygiene:** added `aniworld`, `hudsonrock`,
  `rusfootball`, `patched.sh`, `omg.lol`, `boardgamegeek`, `giphy`, `trello`,
  `discord`, `mastodon.cloud/xyz`, `mstdn.io/social`, plus root-only URLs;
  `--no-recursion` added to maigret manifest flags.

### Verification evidence

- `python -m pytest -q --tb=short` → **`688 passed, 18 skipped in 93.96s`**
  (baseline 676 preserved + new suite). New
  `tests/test_phase17_selftest_fixes.py`: **12 passed**, covering the @/slug
  guard + ingestor reclassification, expanded Sherlock filters, no `person:ali`
  / no doubled handles, email-derived seed provenance + Person link, phone
  E.164/phoneinfoga params, GitHub email → login/repo/OWNS with no email
  username, Ahmia exact-match/zero-match, and `--no-recursion`.
- **Live verification** (`ToolRuntime`, real vault):
  - `github_osint` on `kamranmammadov01@example.com` → **SUCCESS**, 10 entities /
    8 relations, username `kamranmammadov01`, 6 public repositories
    (`ai_osint_hub`, `classactivity`, `SUPER-AGENT-SYSTEM`, `firstpythonrepo`,
    `chess-clone`, `UniConnect_Hackaton`), no username containing `@`.
  - `phoneinfoga` on `+994501234567` → **SUCCESS**, exit 0, 6037-byte output,
    2 entities / 1 relation.
- `python -m hub.cli tools` remains 28/28 AVAILABLE.

### Notes

- Domain Ahmia searches are not exact-filtered (preserves historical domain
  collection); exact matching applies to e-mail/username queries.
- The GitHub collector remains bounded (10 users, 10 commit results, 30 repos
  per hydrated login, 200 repo cap) and all secondary failures stay non-fatal.
- Live GitHub and phoneinfoga outputs are only summarized here (no secrets).

## Final state

All five original phases, the toolchain-provisioning directive, and Phases 7–9
are complete. `git log`:
```
Phase 1: baseline audit + DSH_STATE anchor (64 tests green, Windows fcntl break confirmed)
Phases 2-4: ERKG provenance+WAL, hardened tool runtime, hypothesis pivot engine (369 tests green)
Phase 5: evidence-cited dossier, CLI+MCP parity, live smoke, docs (371 tests green)
Toolchain provisioning: managed dirs + WSL2 bridge + doctor/provision, 17/17 tools (414 tests green + 5 live toolchain tests)
Phases 7-9: 7 native passive collectors + maigret fix (24/24), multi-clue intake/hypotheses,
            FastAPI web workbench + SSE + printable HTML dossier (491 tests green + 12 live tests)
Phase 10: 5 API providers + credential vault + secret redaction + auth-aware pivots +
          Web API Keys drawer + CLI auth (28/28 tools, 586 tests green + live API smoke)
Phase 11: holehe precision + seed-first pivoting + transliteration intake +
          interactive graph/SSE lifecycle (606 tests green)
Phase 12: hierarchical LOCATED_IN + in-run circuit breaker + institutional domain
          seed wave + GitHub/maigret resilience + graph de-clutter (621 tests green)
Phase 13: theHarvester banner/config hygiene + multi-part public suffixes +
          native snscrape probe + hypothesis/Sherlock noise filters (636 tests green)
Phase 14: complete seed coverage/rescue round-robin + provider rate-limit
          cooldown + Web budget 16/20 defaults (649 tests green)
Phase 15: strict free-text handles + maigret target/soft-404 filtering +
          non-functional role attributes + radial graph fit & transient UX
          (666 tests green)
Phase 16: full-handle maigret + photon static-asset/page caps + empty-attribute
          guard + resolved-IP Shodan/Censys pivots & 24h cooldown (676 tests green)
Phase 17: @-free usernames + email-derived seed handles + GitHub email→user/repo
          pivot + Ahmia exact-match + AZ E.164 phones (688 tests green)
Phase 18: Hybrid AI + Vision Forensics + Graph Analytics/Timeline/Diff/Waves +
          32/32 tools + Gruvbox Material Light Cytoscape Workbench + MCP App UI
          (723 passed, 18 skipped)
```

## Phase 18 — Hybrid AI, Vision Forensics, Graph Analytics & Gruvbox Workbench (2026-11-27)

### Delivered

- **Shared Contracts & AI Insights Store (`hub/models.py`, `hub/erkg/store.py`):**
  kept `EpistemicStatus` strictly 6 values; added `PROVENANCE_AI_INFERRED`,
  `PROVENANCE_VLM_EXTRACTED`, `PROVENANCE_MEDIA_FORENSICS`, `SourceKind.AI_REFLECTION`/`VLM`,
  non-functional hash/AI attribute keys, `InvestigationConfig` options (`parallel_pivots=1`,
  `ai_reflection_auto=False`, `ai_vision_enabled=False`), and `ai_insights` SQLite table
  (`add_ai_insight`, `list_ai_insights`).
- **Hybrid Offline + Online AI Layer (`hub/ai/`, `hub/security/quarantine.py`):**
  `AIConfig` (`enabled=False` default) persisted at `$AI_OSINT_HUB_HOME/ai_config.json` (0600,
  masked previews, keys registered with `hub.security.redaction`; isolated from `~/.dsh`,
  `~/.claude`, `~/.codex`). Pure-`httpx` support for Ollama (8 GB VRAM defaults: `gemma4`,
  `qwen2.5vl:7b`, `embeddinggemma`, `num_ctx=8192`), LM Studio, Gemini, DeepSeek, and
  OpenAI-compatible providers, offline char n-gram TF-IDF + Jaro-Winkler embeddings, and
  quarantined `run_case_reflection` (`AI_INFERRED`, `direct=False`, confidence ≤ 0.35).
  Added `VISUAL_SECURITY_SYSTEM_PROMPT`, `sanitize_visual_text`, `wrap_visual_untrusted`,
  and `detect_visual_injection`.
- **Graph Analytics, Parallel Pivots & 32-Tool Registry (`hub/erkg/analytics.py`,
  `hub/erkg/graph.py`, `hub/investigation/engine.py`, `hub/tools/`):** pure-Python
  degree & Brandes betweenness centrality, connected components, label-propagation
  communities, Tarjan bridges, `shortest_path` evidence chains, perceptual-hash clustering
  (Hamming ≤ 6 / exact `mmh3`), `build_timeline`, `diff_investigations`, bounded parallel
  waves (`step_batch` / `parallel_pivots`), and 4 new passive tools (`crtsh_lookup`,
  `asn_bgp_lookup`, `favicon_hash`, `media_forensics`) → **32/32 AVAILABLE**.
- **Enterprise Matte Workbench, Editorial HTML Dossier & MCP App (`hub/web.py`,
  `hub/static/vendor/cytoscape.min.js`, `hub/reporting.py`, `hub/service.py`, `hub/cli.py`,
  `hub/mcp_server.py`):** Gruvbox Material Light (`#fbf1c7`/`#f9f5d7`/`#3c3836`/`#af3a03`)
  3-pane Cytoscape.js 3.35.0 + synchronized SVG workbench, zero `innerHTML`/glassmorphism,
  REST endpoints (`/analytics`, `/timeline`, `/diff`, `/step-batch`, `/api/ai/*`, `/reflect`,
  `/api/media/analyze`), CLI (`analytics`, `timeline`, `diff`, `ai status|reflect`), MCP
  tools + `ui://ai-osint-hub/workbench.html` (`aux_pane`/`global` entrypoints), and
  Gruvbox editorial HTML dossiers with CSP headers.

### Verification evidence

- Independent Security Audit: **0 Critical / 0 High / 0 Medium** defects across all `hub/` changes.
- `python -m hub.cli tools` → **`32/32 AVAILABLE · auth-ready 30/32`**.
- `python -m pytest -q --tb=short` → **`723 passed, 18 skipped`** (0 failures; +35 new offline tests across `test_ai_layer.py`, `test_vision_media.py`, `test_graph_analytics_collectors.py`, and `test_workbench_gruvbox_security.py`; 18 skipped are opt-in `AI_OSINT_HUB_LIVE=1` live tests).

## Blockers
None.
