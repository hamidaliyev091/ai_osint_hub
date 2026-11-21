> **HISTORICAL DOCUMENT (pre-v2, 2026-06-26).** This file describes the v1 JSON-file orchestrator, which was replaced by the ERKG + pivot engine. Current architecture: [README.md](README.md) and [DSH_STATE.md](DSH_STATE.md).

# PROJECT_BRAIN.md — AI OS Internal Knowledge Document

> **Source of truth: code.** Architecture docs, plans, comments verified against code.
> Generated 2026-06-26. Update after major changes.

---

## System Summary

An autonomous agent runtime for cybersecurity reconnaissance inside Claude Code.
The AI (DeepSeek V4 Pro) is the reasoning engine. Python modules are deterministic
hands. The controller loop — `orchestrate.py` — is the central organizing principle.

**Entry point:** `python3 -m hub.orchestrate --init '{"raw_input":"..."}'`
**MCP server:** `python3 -m hub.mcp_server` (Unix socket: `~/.ai_osint_hub/mcp.sock`)
**State root:** `/tmp/ai_osint_hub/state/`
**Tools registered:** 9 tools (4 passive V1 + 5 active V2). All `dangerous=False`.
**Python files:** 18 modules, ~3,200 lines
**Decision model:** AI receives ranked candidates, picks one via `selected_action_id`,
can override score ordering with `override_reasoning`.

---

## Repository Map

```
/root/ai_osint_hub/
├── .env                          # GOOGLE_API_KEY + GOOGLE_CX
├── requirements.txt              # httpx>=0.28.0, rich>=13.0.0
├── PROJECT_BRAIN.md              # This file
│
├── skills/ai-os-orchestrator/
│   ├── SKILL.md                  # Reasoning policy (~100 lines)
│   └── references/
│       └── tool_catalog.md       # Manual markdown (NOT auto-generated)
│
├── hub/
│   ├── __init__.py               # Empty
│   ├── orchestrate.py            # ★ Controller (733 lines) — init/step/status/report
│   ├── registry.py               # Tool metadata (222 lines)
│   ├── cooking.py                # Deterministic logic (443 lines)
│   ├── executor/
│   │   ├── __init__.py           # Empty
│   │   ├── runtime.py            # Subprocess execution (143 lines)
│   │   └── parsers/
│   │       ├── __init__.py       # Empty
│   │       ├── holehe.py         # 75 lines (V1)
│   │       ├── maigret.py        # 81 lines (V1)
│   │       ├── h8mail.py         # 92 lines (V1)
│   │       ├── theharvester.py   # 178 lines (V1)
│   │       ├── nmap.py           # Real — XML + grepable port/service parser (V2)
│   │       ├── amass.py          # Real — JSON subdomain/IP parser (V2)
│   │       ├── hashcat.py        # Real — hash:password extraction parser (V2)
│   │       ├── hydra.py          # Stub — credential regex parser (V2)
│   │       └── gobuster.py       # Stub — path/status extractor (V2)
│   ├── mcp_server.py             # New — MCP server (FastMCP, Unix socket, 4 tools) (V2)
│   ├── graph/
│   │   ├── __init__.py           # Empty
│   │   └── memory.py             # Dict-based adjacency (328 lines)
│   ├── planner/
│   │   ├── __init__.py           # Empty
│   │   ├── candidates.py         # Scoring + pruning (385 lines)
│   │   └── evaluate.py           # Stop logic (155 lines)
│   └── schemas/
│       └── ai_decision.schema.json  # 37 lines
│
└── tests/                        # Empty (no tests written)
```

### Dependency Graph

```
orchestrate.py
├── graph/memory.py       (ExposureGraph, ingest_entity, link_*)
├── registry.py           (get_tool, is_dangerous, for_entity, ...)
├── cooking.py            (parse_raw_input, generate_usernames, infer_emails,
│                          expand_hypotheses, deduplicate, CONFIDENCE)
├── executor/runtime.py   (execute as run_tool)
├── executor/parsers/     (holehe, maigret, h8mail, theharvester)
└── planner/
    ├── candidates.py     (generate_candidates)
    └── evaluate.py       (check_hard_stops, check_soft_stops, compute_completeness)

candidates.py
├── registry.py           (get_tool, for_entity, get_tool_class_weight)
└── graph/memory.py       (ExposureGraph)

evaluate.py
└── graph/memory.py       (ExposureGraph)

runtime.py
└── registry.py           (get_tool, validate)

parsers/
└── cooking.py            (extract_urls, extract_usernames_from_urls, extract_emails)

cooking.py
└── (stdlib only: re)
```

**Key observation:** `orchestrate.py` is the only module that imports from all others.
It is the integration hub. `candidates.py` and `evaluate.py` depend only on registry + graph.
Parsers depend only on cooking.py's extractors.

---

## Runtime Flow

### --init

```
main()
  → cmd_init(raw_input, constraints)
    → parse_raw_input(text)                         # cooking.py — NL → structured entities
    → generate_usernames(persons, suffixes, interests)  # cooking.py — 15 rule functions
    → infer_emails(parsed_usernames[:10])           # cooking.py — only for directly-provided usernames
    → graph.add_node() for persons, associates, emails, domains, usernames
    → link_person_to_username() / link_username_to_email()
    → graph.add_node() for generated usernames (cap 30) at confidence 0.30
    → graph.add_node() for inferred emails at confidence 0.25
    → generate_candidates(graph, history=[])        # planner/candidates.py
      → _generate_all() → _filter_no_value() → _group_similar() → _score() → _top_k_diverse()
    → compute_completeness(graph, history=[])       # planner/evaluate.py
    → _save_state()                                  # investigation.json + graph.json
    → _save_candidates()                             # candidates.json
    → return {status, target_id, candidate_actions, graph_summary, ...}
```

### --step

```
main()
  → cmd_step(target_id, selected_action_id, action, constraints)
    → _load_state()                                 # Loads investigation.json + graph.json + turn_*.json
    → _lookup_action(target_id, selected_action_id) # Validates against stored candidates.json
    → [if _hypothesis_expand]                       # Virtual action branch
      → expand_hypotheses(all_entities, graph)
      → graph.add_node() for each new hypothesis
      → generate_candidates() → _save_candidates()
    → [else]                                        # Real tool branch
      → run_tool(tool_name, params)                  # executor/runtime.py — subprocess
        → get_tool() → registry_validate() → safety gate → build command → subprocess.run()
      → PARSERS[tool_name].parse(raw_stdout)         # Tool-specific parser
      → deduplicate(new_entities)                    # cooking.py
      → ingest_entity(graph, entity, params, tool, ts)  # graph/memory.py — relationship dispatch
      → expand_hypotheses(cleaned, graph)            # cooking.py — generate new leads
      → Save raw output to raw/{tool}_{turn}.txt
      → generate_candidates(graph, updated_history)  # New candidates from updated state
      → _save_candidates()
      → check_hard_stops() + check_soft_stops()
    → _save_state()                                  # investigation.json + graph.json + turn_NNN.json
    → _build_step_response()
    → return {turn, new_entities, candidate_actions, hard_stops, soft_stops, stop_recommendation}
```

### --status

```
main()
  → cmd_status(target_id)
    → _load_state()
    → generate_candidates(graph, history)
    → return {status, investigation, graph_summary, candidate_actions, last_3_turns}
```

### --report

```
main()
  → cmd_report(target_id)
    → _load_state()
    → Build markdown: entity tables by type, relationship counts, recommendations
    → investigation["status"] = "complete"
    → return {status: "complete", report_md, graph_summary}
```

---

## Core Objects

### CandidateAction (candidates.py)
```
action_id: str              # "act_000" (index-based, unique within turn)
tool: str                   # "holehe" | "h8mail" | "maigret" | "theHarvester" | "_hypothesis_expand"
params: dict                # {"email": "x@y.com"} — ready to pass to runtime.execute()
entity_target: str          # "email:analyst@example.com" (node_id in graph)
entity_type: str            # "email" | "username" | "domain" | "hypothesis"
entity_confidence: float    # 0.0–1.0
expected_yield: str         # "15–25 services" (human-readable)
score: CandidateScore       # Breakdown below
tool_cost: {time_s, passive, dangerous}
dangerous: bool
active: bool
rationale: str              # "unverified entity — confirming would increase information gain"
```
**Lifecycle:** Generated fresh each turn by `generate_candidates()`. Persisted as
`candidates.json` snapshot. AI selects one via `selected_action_id`. Destroyed
when next turn generates new candidates.

### CandidateScore (candidates.py)
```
total: float                   # Final score 0.0–1.0+ (not clamped, can exceed 1.0)
base_weight: float             # From TOOL_CLASS_WEIGHTS (0.30–0.70)
confidence_multiplier: float   # 0.5 / 0.8 / 1.0 / 1.3 (based on entity confidence range)
unexplored_bonus: float        # 0.2 * (unexplored_neighbors / total_neighbors)
redundancy_penalty: float      # 0.0 / 0.2 / 0.5 (based on prior yield of same tool)
cost_factor: float             # min(1.0, 120 / max(60, timeout_s))
```
**Formula:** `total = max(0.05, ((base + unexplored_bonus) * conf_mult - redundancy_penalty) * cost_factor)`

### Graph Node (graph/memory.py)
```
node_id: str               # "email:analyst@example.com" — deterministic from type+value
type: str                  # person | email | username | domain | ip | phone | service | breach | credential
value: str                 # Canonical value (lowercase, stripped)
confidence: float          # 0.0–1.0 (default 0.5)
sources: list[str]         # ["raw_input"] | ["holehe:analyst@example.com"] | ["hypothesis_generation"]
first_seen: str            # ISO timestamp
last_seen: str             # ISO timestamp
metadata: dict             # {"registered": true, "url": "https://...", "username_hint": "..."}
```
**Lifecycle:** Created during init (from parsed input + hypotheses), updated during
step (from tool output). Confidence updated via `max(existing, new)`. Never deleted.

### Graph Edge (graph/memory.py)
```
source: str                # node_id
target: str                # node_id
type: str                  # HAS_USERNAME | HAS_EMAIL | REGISTERED_ON | EXPOSED_IN | LINKED_TO | RESOLVES_TO | RELATED_TO | INFERRED_FROM
confidence: float          # 0.0–1.0 (default 0.5)
source_tool: str           # "raw_input" | "holehe" | "hypothesis_generation"
metadata: dict
```
**Lifecycle:** Created during entity ingestion (`ingest_entity()`) or init graph seeding.
Deduplicated by (source, target, type). Never deleted.

### Investigation Snapshot (investigation.json)
```
target_id: str             # "case_20260626_144500"
created_at: str            # ISO timestamp
updated_at: str            # ISO timestamp
status: str                # "active" | "complete" | "terminated"
raw_input: str             # Original user input
constraints: dict          # {"max_depth": 5, ...}
turn_count: int
total_nodes: int
total_edges: int
completeness: float        # 0.0–1.0
```

### Candidate Snapshot (candidates.json)
```
{
  "act_000": {"tool": "holehe", "params": {"email": "x@y.com"}, "entity_type": "email", "entity_target": "email:x@y.com"},
  "act_001": {...},
  ...
}
```
**Purpose:** Validates AI's `selected_action_id` in the next `--step` call.
Stored atomically via `.tmp` rename.

### AI Decision (ai_decision.schema.json)
```
decision: "execute" | "terminate" | "broaden"
selected_action_id: str    # Required if execute
override_reasoning: str    # Required if non-top-ranked
termination_reason: str    # Required if terminate
broaden_rationale: str     # Required if broaden
timestamp: str             # ISO datetime
```
**Validation:** Schema defined but NOT enforced at orchestrator level.
Orchestrator only validates that `selected_action_id` exists in stored `candidates.json`.

### Registry Entry (registry.py)
```
ToolMeta dataclass:
  name, display_name, description
  entity_input: list[str]          # ["email"] | ["username"] | ["domain", "email"]
  entity_output: list[str]         # ["service", "username_hint", "profile_url"]
  params: dict                     # {"email": {"type": "string", "format": "email", "required": true}}
  dangerous: bool, active: bool
  tool_class: str                  # "email_service_mapping" | "breach_lookup" | "username_enumeration" | "domain_harvesting"
  default_priority: float          # 0.8–0.9
  timeout_s: int                   # 60–300
  binary: str                      # CLI binary name
  cli_map: dict                    # {"email": "--email"} — None = positional
  parser: str                      # "hub.executor.parsers.holehe:parse"
```

### Parser Output (all parsers)
Each `parse()` returns `list[dict]` where each dict has:
```
type: str                  # "service" | "breach" | "email" | "domain" | "ip" | "url" | "username"
value: str                 # Canonical value
confidence: float          # Parser-assigned (0.55–0.95 depending on parser + status)
sources: list[str]         # ["holehe:target@email.com"]
source: str                # "tool_output"
metadata: dict             # Parser-specific extras
```

---

## Module Responsibilities

| Module | Real Responsibility | Lines |
|--------|-------------------|-------|
| `orchestrate.py` | Controller loop, state persistence, module wiring, confidence assignment, report formatting | 733 |
| `registry.py` | Tool metadata, validation, entity→tool discovery | 222 |
| `cooking.py` | NL parsing, username generation (15 rules), email inference, entity extraction, normalization, dedup, confidence scoring, hypothesis expansion | 443 |
| `graph/memory.py` | Dict-based adjacency graph, relationship dispatch (`ingest_entity`), serialization | 328 |
| `runtime.py` | Subprocess execution, safety gate, command construction, timeout | 143 |
| `candidates.py` | Context-sensitive scoring (5 factors), 4-stage pruning, top-k diversity | 385 |
| `evaluate.py` | Hard stops (3 types), soft stops (4 types), completeness heuristic (3 factors) | 155 |
| `mcp_server.py` | FastMCP server wrapping orchestrator, 4 MCP tools, Unix socket via uvicorn | 132 |
| `parsers/*.py` | Tool-specific raw output → structured entity parsing | 426 total |

---

## Agent Decision Model

### How the AI Actually Selects Actions

1. Orchestrator returns `candidate_actions[]` sorted by `score.total` descending
2. AI reads candidates, applies SKILL.md evaluation criteria (confirmation > generation, density, passive > active, cost)
3. AI returns `{"decision": "execute", "selected_action_id": "act_XXX", "override_reasoning": "..."}`
4. Orchestrator looks up `act_XXX` in stored `candidates.json` → executes stored tool+params
5. If action_id not found → error returned, AI must re-evaluate

### Override Reality

- AI CAN override score ordering by selecting any valid action_id
- `override_reasoning` field is documented but never validated or enforced
- No constraint prevents AI from picking the lowest-scored candidate
- No constraint forces AI to provide override_reasoning when deviating from top rank

### Score Dominance Problem

The scoring formula has systematic biases:

1. **Email tools dominate username tools on hypotheses:** An unconfirmed email (conf=0.25) with holehe (base=0.70, cost=1.0) scores 0.56. A confirmed username (conf=0.85) with maigret (base=0.60, cost=0.4) scores 0.24. Email hypothesis > confirmed username by 2.3x.

2. **Cost factor is the dominant penalty:** Maigret's 300s timeout → cost_factor=0.4, cutting its score by 60%. This makes maigret systematically lose to cheaper tools even when it targets higher-confidence entities.

3. **Confirmation bonus range is narrow:** Only entities at 0.3–0.6 confidence get the 1.3x multiplier. Entities at 0.7–0.89 get 1.0x (no bonus). The "confirmation sweet spot" is tight.

---

## State Persistence

### Storage Backend
Plain JSON files. Atomic writes via `.tmp` → `os.rename()`. No database.

### Directory Structure Per Case
```
/tmp/ai_osint_hub/state/{target_id}/
├── investigation.json       # Metadata, turn count, completeness
├── graph.json               # Full ExposureGraph (nodes dict + edges list)
├── candidates.json          # {action_id: {tool, params, entity_type, entity_target}}
├── turn_001.json            # Per-turn: action, result, hard_stops, soft_stops
├── turn_002.json
├── turn_NNN.json
├── SUMMARY.md               # Human-readable log, appended each turn
└── raw/                     # Raw tool outputs
    ├── holehe_001.txt
    ├── maigret_001.json
    └── ...
```

### What Persists Across Turns
- Full graph state (all nodes, all edges, all confidence scores)
- Investigation metadata (turn count, completeness, status)
- Per-turn history (last N turns — all kept, no rotation)
- Raw tool outputs (never cleaned up)
- Candidate snapshot (last turn only — overwritten each turn)

### What Does NOT Persist
- The AI's decision JSON (stored inside turn record as `ai_decision` field but currently EMPTY — not populated by orchestrator)
- Token usage / context state
- Tool execution errors beyond the turn record status field

---

## Safety Model

### Dangerous Tool Gate
- `runtime.execute()` checks `tool_meta.dangerous` before execution
- If dangerous AND `allow_dangerous=False` → returns `"blocked_dangerous"` status
- `allow_dangerous` comes from `constraints["dangerous_tools_enabled"]` (default: absent → False)
- **0 of 9 registered tools are dangerous** — all tools have `dangerous=False` per user directive; safety gate code preserved but never triggered

### Active vs Passive
- Tools have `active: bool` metadata field
- All 4 registered tools are `active=False` (passive)
- The `active` flag is displayed in candidate metadata but NOT enforced by any gate
- An active tool could be registered without any runtime enforcement

### What Is NOT Protected
- No rate limiting — tools can be called as fast as the AI sends `--step`
- No target scope validation — orchestrator executes whatever params the AI sends
- No output sanitization — raw tool output stored as-is
- No credential masking — breach data with hashes stored in plain JSON
- No API key rotation — `.env` key loaded but never validated

---

## Architecture Drift

### Plan vs Reality

| Plan | Reality | Severity |
|------|---------|----------|
| 6 tool adapters (holehe, maigret, h8mail, theHarvester, nmap, amass) | 4 (holehe, maigret, h8mail, theHarvester) | Low — v2 tools deferred |
| ~1,390 lines Python | ~2,700 lines | Medium — systematic underestimation |
| `tool_catalog.md` auto-generated from registry | Manual markdown, needs `export_catalog()` re-run | Low |
| SKILL.md ~80 lines | 100 lines | Low |
| `orchestrate.py` ~300 lines | 733 lines | High — controller absorbs more than planned |
| NetworkX in V2 | Not imported, not in requirements | None — correct |
| No hardcoded pipelines | Candidate scoring creates implicit priority: email tools > username tools > hypothesis expansion | Medium — emergent but systematic |
| AI override reasoning enforced | Field documented, not validated | Medium |
| `ai_decision.schema.json` validated at orchestrator | Schema exists, not loaded or validated by orchestrator | Medium |
| `selected_action_id` validated | Yes — validated against stored candidates.json | None — correct |
| `_save_candidates` in hypothesis_expand branch | Present | None — correct |
| `ingest_entity()` in graph module | Present — relationship dispatch moved from orchestrator | None — correct |
| `CONFIDENCE` constants in cooking.py | Present | None — correct |

### Hidden Coupling

1. **Parser dispatch is hardcoded** in `orchestrate.py` (line 43-48). Adding a new tool requires editing orchestrator.
2. **Tool-specific CLI flags** in `runtime.py` — holehe gets `--no-color` appended (line 88). No registry field for extra flags.
3. **Hypothesis expansion suffixes** hardcoded in `cooking.py` — `["1", "123", "007", "091", "99", "0", "official", "real"]`. Adding new suffix rules requires editing cooking.py.
4. **Report entity type order** hardcoded in `cmd_report` — `["person", "email", "username", "domain", "ip", "phone", "service", "breach", "credential"]`. New entity types need manual insertion.
5. **Entity→relationship dispatch** in `ingest_entity()` only handles `"service"` and `"breach"` types. New entity types that need relationship creation require editing graph module.

---

## Hidden Risks

### 1. Unbounded Graph Growth
Graph nodes are never deleted. Hypothesis expansion adds nodes each turn. With 10 turns, the graph could reach hundreds of nodes. Summary compression (used for AI context) caps at 2KB, but the full `graph.json` grows unboundedly.

### 2. No Tool Execution Time Tracking
`elapsed_seconds` in `check_hard_stops` is hardcoded to `0`. The time budget hard stop never triggers because elapsed time is not computed from turn timestamps.

### 3. Parser Failure Silenced
`cmd_step` wraps parser execution in `try/except Exception` and silently sets `new_entities = []`. A broken parser produces zero entities with no error surfaced to the AI.

### 4. Single Point of Failure
`orchestrate.py` is 733 lines with no internal module boundaries. It handles init, step, status, report, state persistence, candidate persistence, relationship creation, hypothesis expansion, and report formatting. If this file breaks, the entire system is down.

### 5. No Test Coverage
The `tests/` directory is empty. No unit tests, no integration tests, no fixtures. All verification was manual.

### 6. Tool Binary Assumption
`runtime.py` assumes all tool binaries are in PATH. If a binary is missing, it returns `"tool_not_found"` status but the orchestrator's candidate generation still offers that tool.

### 7. JSON Schema Not Enforced
`ai_decision.schema.json` exists but is never loaded or validated by the orchestrator. The AI could return malformed JSON and the orchestrator would only catch it at the `json.loads()` level — no field validation.

### 8. State Directory Growth
17 case directories already exist from testing. Raw tool outputs are never cleaned up. `SUMMARY.md` grows unboundedly. No retention policy.

---

# Hostile Architecture Audit

> **Audit date:** 2026-06-26. **Status after fixes:** 5/5 resolved (see Resolution Log below).

# Resolution Log

## Verdict

**Autonomy: PARTIAL**

The system is NOT fake. The AI genuinely selects actions from dynamically generated
candidates that change with graph state. No hardcoded execution pipeline exists.
Different inputs produce different candidate sets. The AI can override score
ordering with `override_reasoning`.

But the system is NOT fully autonomous. The scoring formula creates a systematic
bias: email tools on low-confidence hypotheses consistently outscore username
tools on confirmed entities. The AI CAN override, but the numbers push hard in
one direction. This is soft determinism — guidance strong enough to shape behavior
predictably, not a hardcoded pipeline.

**Distinction from fake autonomy:** A fake-autonomous system would have a fixed
`maigret → holehe → h8mail` sequence encoded in control flow. This system has
`generate_candidates() → score() → AI_selects()`. The sequence emerges from
state + scoring + AI judgment. That's genuine agentic architecture with a
scoring pathology.

## P0 — Critical

### P0-1: ~~Hard Stop Time Budget Is Dead Code~~ [FIXED]
**File:** `orchestrate.py:493` — now computes `elapsed` via `_compute_elapsed(history, timestamp)` from turn timestamps.
**Fix:** `_compute_elapsed()` added — parses ISO timestamps from first and current turn, returns `total_seconds()`.

### P0-2: ~~Init Constraints Silently Dropped During Step~~ [FIXED]
**File:** `orchestrate.py` — now merges stored `investigation["constraints"]` with CLI-passed constraints before execution.
**Fix:** `constraints = {**stored_constraints, **constraints}` added after `_load_state()` in `cmd_step`.

## P1 — Important

### P1-1: ~~Scoring Systematically Penalizes Confirmed Entities~~ [FIXED]
**Evidence before fix:**
| Candidate | Score Before | Score After |
|-----------|-------------|-------------|
| holehe on inferred email (0.25) | 0.56 | 0.49 |
| maigret on confirmed username (0.85) | 0.24 | 0.38 |

**Fix:** Cost factor changed from `min(1.0, 120/max(60,t))` → `1.0/(1.0+0.15*max(0,(t-60)/60))`.
Gap narrowed from 2.3x to 1.3x. Maigret at 300s now keeps 63% of its score (was 40%).
AI override from "confirmation over generation" is now a reasonable judgment call,
not fighting a 2.3x inversion.

### P1-2: ~~Parser Failures Silently Produce Zero Entities~~ [FIXED]
**File:** `orchestrate.py` — `except Exception` now captures `type(e).__name__: {str(e)[:200]}` into `parse_errors[]`, threaded into turn record and step response. AI sees parser errors in the turn result.

### P1-3: No Tools Registered as Dangerous
The safety gate in `runtime.py` checks `tool_meta.dangerous` before execution.
But all 4 registered tools have `dangerous=False`. Hashcat, hydra, nmap, gobuster
are not in the V1 registry.

**Impact:** The safety gate is real code that works correctly — it just has zero
coverage. When dangerous tools are added, the gate will activate. But currently
the system appears safer than it is because no dangerous paths exist yet.

## P2 — Minor

### P2-1: ~~JSON Decision Schema Not Validated~~ [FIXED]
New `--decide` endpoint + `validate_decision()` function enforces: required fields (`decision`, `timestamp`), valid enum values, conditional requirements (`selected_action_id` for execute, `termination_reason` for terminate, `broaden_rationale` for broaden). No external dependencies — manual validation.

### P2-2: Tool-Specific Flags Hardcoded in Runtime
**File:** `runtime.py:88`
```python
if tool_name == "holehe":
    cmd_parts.append("--no-color")
```
Adding a new tool that needs extra flags requires editing `runtime.py`. The
registry has no field for extra CLI flags.

### P2-3: Parser Dispatch Hardcoded in Orchestrator
**File:** `orchestrate.py:43-48`
```python
PARSERS = {
    "holehe": holehe.parse,
    "maigret": maigret.parse,
    "h8mail": h8mail.parse,
    "theHarvester": theharvester.parse,
}
```
Adding a new tool requires editing this dispatch dict. The registry's `parser`
field (`"hub.executor.parsers.holehe:parse"`) is a dotted path string that could
be dynamically imported — but it's never used for dispatch.

### P2-4: No Test Coverage
`tests/` directory is empty. Zero unit tests, zero integration tests, zero fixtures.
All 17 case directories in `/tmp/ai_osint_hub/state/` are manual test artifacts.

## Most Dangerous Hidden Bug

**Line 493 of `orchestrate.py`: `elapsed = 0`**

This is a one-line bug that disables an entire class of safety constraint.
Combined with:
- No max_depth enforcement if set high
- Scoring that can produce viable-looking candidates indefinitely (hypothesis expansion always available at score 0.39)
- Soft stops that the AI can override

...an investigation could loop until disk fills with graph state. The time budget
guard that should prevent this is dead code.

## Ship Decision

**APPROVED** (5/5 critical+important fixes applied 2026-06-26)

| Issue | Status |
|-------|--------|
| P0-1: Dead time budget | ✅ Fixed — `_compute_elapsed()` from history |
| P0-2: Constraints dropped | ✅ Fixed — merge stored + CLI constraints |
| P1-1: Scoring penalty | ✅ Fixed — cost factor gentler curve (1.3x gap vs 2.3x) |
| P1-2: Parser errors silent | ✅ Fixed — `parse_errors[]` in turn record |
| P2-1: Schema unvalidated | ✅ Fixed — `--decide` endpoint with `validate_decision()` |

Remaining P2 items (P2-2 tool flags, P2-3 parser dispatch, P2-4 test coverage)
are deferred to V2 — they require registry schema changes and new tool additions.

---

# Final Hostile Audit — Hidden Failure Modes

> **Audit date:** 2026-06-26. **Scope:** loop termination, state consistency, resume,
> candidate validity, tool failure propagation, safety bypasses, business logic drift,
> fake autonomy. **No style feedback. Bugs only.**

## 1. Loop Termination Safety

### P0-3: ~~Indefinite Loop via Hypothesis Expansion + AI Override~~ [FIXED]
**Fix:** New hard stop `consecutive_zero_yield` in `evaluate.py:check_hard_stops()`.
Triggers when last 3 turns ALL have `new_entity_count == 0`. This is non-overridable
(`force_terminate`). Catches hypothesis expansion loops AND persistent tool failures.
Tested: after 3 zero-yield turns, `force_terminate` triggered at turn 4.

### P1-4: Broadend + Execute Cycle Can Suppress Soft Stops
**Files:** `orchestrate.py:394-436`, `evaluate.py:66-76`

`_hypothesis_expand` creates turn records with `new_entity_count > 0` on first call.
A cycle of `broaden → execute → broaden → execute` alternates between
hypothesis generation and tool execution. Each broaden resets the diminishing
returns counter by producing new entities. Each tool execution on those new
entities also produces entities. This cycle can sustain itself past the 3-turn
diminishing returns window.

**Evidence:** `evaluate.py:66-76`: only checks `last_3_yields`. A pattern of
`[0, 5, 0, 5, 0, 5]` never triggers diminishing returns because any 3-turn
window that includes a "5" passes the `< 2` check.

**Risk:** Medium. Requires AI to intentionally cycle broaden+execute. But the
scoring guides toward this when no high-score real actions remain.

## 2. State Consistency

### P0-4: ~~Candidates Saved Before State — Crash Creates Inconsistency~~ [FIXED]
**Fix:** Reordered in `cmd_step`: `_save_state()` now called BEFORE `_save_candidates()`.
If crash occurs between them, state is intact and candidates are missing (regenerated
on next `--status`). Old order: candidates saved first, crash left stale `candidates.json`
ahead of `graph.json`. Hypothesis expansion branch already had correct order.

### P1-5: SUMMARY.md Not Atomic
**File:** `orchestrate.py:133-143`

`SUMMARY.md` is appended via `open(path, "a")` without atomic write. All other
files use `.tmp → rename`. Crash mid-write leaves partial Markdown. Not used for
state recovery, but could confuse human operators reading the log.

## 3. Resume Correctness

### P1-6: ~~cmd_status Regenerates Candidates, Making Stored Snapshot Stale~~ [FIXED]
**Fix:** `cmd_status` now calls `_save_candidates()` after regenerating. Resume flow (`--status` → pick candidate → `--step`) works without stale snapshot errors.

## 4. Tool Failure Propagation

### P0-5: ~~AI Cannot Distinguish Timeout from Empty Results~~ [FIXED]
**Fix:** `_build_step_response` now returns `execution_status` ("success"/"timeout"/"error"/"tool_not_found"), `parse_errors[]`, and `duration_ms`. AI can distinguish: timeout (retry/pivot) vs error (tool broken) vs success+0 entities (legitimate empty) vs success+parse_errors (parser broken).

## 5. Safety Bypass Paths

### P1-7: Virtual Actions Bypass Runtime Safety Gate
**Files:** `orchestrate.py:393-436`

`_hypothesis_expand` is handled with a direct `expand_hypotheses()` call.
It never passes through `runtime.execute()` or its safety gate. Currently harmless
(hypothesis expansion is safe). But if future virtual actions are added (e.g.,
`_auto_crack`, `_auto_exploit`), they would bypass the dangerous tool check at
line 385.

**Fix:** Add a virtual action registry with its own `dangerous` flag, or route
virtual actions through a common validation path.

### P1-8: No `dangerous: true` Tools Registered — Gate Untested
**Files:** `registry.py:50-130`, `runtime.py:83`

The safety gate in `runtime.py` is real code that works correctly. But all 4
registered tools have `dangerous=False`. The gate has never been exercised in
production. When hashcat/hydra are registered in V2, the gate activates for
the first time — untested in integration.

## 6. Business Logic Drift

### P2-5: Hardcoded Tool List in cmd_init
**File:** `orchestrate.py:314-316`

```python
"available_tools": [
    f"{t}:{','.join(get_tool(t).entity_input)}"
    for t in ["holehe", "maigret", "h8mail", "theHarvester"]
],
```
Tool names are hardcoded. Adding a tool to the registry won't make it appear
in `--init` output. Use `list_tools()` instead.

### P2-6: Holehe CLI Flag Hardcoded in Runtime
**File:** `runtime.py:87-88`

`if tool_name == "holehe": cmd_parts.append("--no-color")` — tool-specific
logic in the generic runtime. Adding tool-specific flags for other tools
requires editing `runtime.py`.

### P2-7: Hypothesis Expansion Suffixes Hardcoded
**File:** `cooking.py:359` — `["1", "123", "007", "091", "99", "0", "official", "real"]`

These suffix variants for username expansion are domain knowledge embedded in
code. Adding new suffix patterns requires editing `cooking.py`.

## 7. Fake Autonomy Check

**Verdict: GENUINE AUTONOMY with scoring bias.**

The system has no hardcoded execution order. Candidate generation is:
`ALL entities × ALL matching tools → score → sort → prune → AI selects`.

The AI can select any candidate regardless of rank. It can override with
`override_reasoning`. Different inputs produce different candidate sets.

**Quantified autonomy:**
- Candidate order is deterministically ranked by score formula
- Score formula has 5 factors (base_weight, confidence_mult, unexplored_bonus, redundancy_penalty, cost_factor)
- Given identical graph state, candidate order is always identical
- The AI has N choices but the ranking is fixed
- A model that always picks `candidates[0]` would follow a deterministic path
- A model that evaluates all candidates against SKILL.md criteria would deviate when justified

**Weaker model behavior:** A model that always picks the top-scored candidate would:
1. Run holehe/h8mail on any email entity first (highest base_weight)
2. Then theHarvester on any domain
3. Then maigret on usernames
4. Then _hypothesis_expand when everything else exhausted

This is a reasonable default strategy. The AI adds value when it overrides:
- "We have confirmed usernames but only inferred emails → pick maigret first"
- "The top-scored candidate was just run last turn with 0 yield → skip it"

**Would I trust this to run unattended for 6 hours?** NO.

Reasons:
1. `max_depth` is the only reliable termination guarantee. If set to 100, the loop runs 100 turns.
2. `time_budget` now works but requires explicit user configuration.
3. Soft stops can be overridden indefinitely. No hard "3 consecutive zero-yield turns → force terminate" rule.
4. Tool execution failures (timeout, crash) are invisible to the AI — it can't adapt.
5. No resource monitoring. Disk fills with raw outputs and graph state.
6. No alerting. Silent failures accumulate invisibly.
7. ~~Candidates-before-state save ordering~~ (FIXED: P0-4)

**All 5 "what would make it trustworthy" items now resolved:**
1. ✅ Consecutive zero-yield hard stop (P0-3)
2. ✅ Execution status + parse_errors surfaced (P0-5)
3. ✅ State saved before candidates (P0-4)
4. ✅ cmd_status saves candidates (P1-6)
5. ⚠ Disk usage cap — deferred to V2 (acceptable for bounded runs)

---

## Final Tally (After Fixes)

| ID | Severity | Status | Issue |
|----|----------|--------|-------|
| P0-3 | Critical | ✅ Fixed | Indefinite loop → `consecutive_zero_yield` hard stop |
| P0-4 | Critical | ✅ Fixed | Crash corruption → state saved before candidates |
| P0-5 | Critical | ✅ Fixed | Blind AI → `execution_status` + `parse_errors` surfaced |
| P1-4 | Important | Open | Broaden+execute cycle suppresses soft stops (mitigated by P0-3) |
| P1-5 | Important | Open | SUMMARY.md not atomic (cosmetic, not used for recovery) |
| P1-6 | Important | ✅ Fixed | cmd_status now saves candidates — resume→step works |
| P1-7 | Important | Open | Virtual actions bypass runtime safety gate (no dangerous virtuals exist) |
| P1-8 | Important | Open | Dangerous tool gate untested (activates when V2 tools registered) |
| P2-5 | Minor | Open | Hardcoded tool list in cmd_init |
| P2-6 | Minor | Open | Holehe CLI flag in generic runtime |
| P0-6 | Critical | ✅ Fixed | Hard stops advisory → pre-execution guard in `cmd_step` |
| P2-7 | Minor | Open | Hypothesis expansion suffixes hardcoded |

**6-hour unattended trust:** YES.

P0-6 fixed 2026-06-26: `cmd_step` pre-execution guard mechanically rejects
execution after any hard stop triggers. Additionally: variant explosion
prevented (confidence threshold 0.5 in `expand_hypotheses`), entity counting
fixed (`add_node` returns `is_new`), and turn_record hard_stops persisted.

Verified: investigation terminates at turn 5 regardless of AI behavior.
Four hard stops enforced at execution boundary. See Final Adversarial Audit.

The investigation now has 4 independent hard stops that cannot be overridden:
1. `no_candidates` — graph exhausted
2. `max_depth` — turn limit (default 5, configurable)
3. `time_budget` — elapsed wall-clock time (computed from turn timestamps)
4. `consecutive_zero_yield` — 3 turns with 0 new entities (stall detection)

If the AI picks `_hypothesis_expand` 3 times in a row and each produces 0 entities,
the investigation force-terminates. If a tool times out 3 times, force-terminate.
If max_depth is reached, force-terminate. If time budget is exhausted, force-terminate.

The AI sees execution status per turn and can adapt: retry after timeout, skip
broken tools, pivot after legitimate empty results. State is crash-consistent
(saved before candidates, atomic writes).

**Caveats for unattended operation:**
- Set `max_depth` explicitly (default 5 is safe but may be too low for deep investigations)
- Set `time_budget_minutes` explicitly (default 30 minutes)
- Do not set `max_depth` above 50 without disk monitoring

---

# Final Adversarial Sign-Off Audit

> **Date:** 2026-06-26. **Scope:** correctness, race conditions, crash corruption,
> invariants, infinite loops, stale state, false autonomy, safety bypasses, resume bugs,
> scoring pathologies. **Second-order failure modes from prior fixes included.**

## Verdict

**APPROVE WITH CONDITIONS**

One P0 remains: hard stops are advisory, not enforced at execution level.
Fixed below. Three P1 issues documented. No other P0 found after adversarial review.

## Remaining Critical Bug: P0-6 — Hard Stops Advisory, Not Enforced

**File:** `orchestrate.py:cmd_step` (lines 321-525)

**Exploit:** `cmd_step` has zero pre-execution guard. An AI that ignores
`stop_recommendation: "force_terminate"` can call `--step` indefinitely.

**Proof:** `cmd_init` with `max_depth=2`. After turn 2, `hard_stops: [max_depth]`,
`stop_recommendation: "force_terminate"`. AI calls `--step` 4 more times.
All 4 execute normally. Turns 3-6 all return `force_terminate` but execute anyway.

**Why current fixes fail:** `check_hard_stops()` triggers at lines 429/514 AFTER
tool execution (line 438). The `force_terminate` string is only in the response
JSON. No code reads it on the NEXT `--step` call and rejects execution.

**Concrete fix:** Add pre-execution guard at the top of `cmd_step`, after loading state:

```python
# Guard: reject execution if investigation is terminated
if investigation.get("status") in ("complete", "terminated"):
    return {"status": "error", "errors": ["Investigation already terminated"]}

# Guard: reject if hard stops triggered last turn (prevent ignore-loop)
if history:
    last_turn = history[-1]
    last_hard_stops = last_turn.get("hard_stops", [])
    if any(s.get("triggered") for s in last_hard_stops):
        return {"status": "error",
                "errors": ["Investigation reached hard stop. Call --report."]}
```

## Remaining Important Bugs (P1)

### P1-9: Time Budget Dead in Hypothesis Expansion Branch
**File:** `orchestrate.py:429-430`
```python
hard_stops = check_hard_stops(graph, constraints, turn_count,
                              0, candidates, history + [turn_record])
```
`elapsed_seconds=0` hardcoded. Time budget never triggers for hypothesis expansion
turns. Minor because expansion is instant (<1ms), but inconsistent with main branch
which uses `_compute_elapsed()`.

### P1-10: Tool stderr Never Persisted
**File:** `orchestrate.py:483-485`
```python
with open(raw_path, "w") as f:
    f.write(result.raw_stdout)
```
`result.raw_stderr` captured by subprocess but never written to disk or surfaced
to AI. If a tool fails and writes the error ONLY to stderr, the AI sees
`execution_status: "error"` with zero context about what went wrong.

### P1-11: cmd_report Sets Status to "complete" Without Saving
**File:** `orchestrate.py:643`
```python
investigation["status"] = "complete"
```
`cmd_report` modifies the in-memory investigation dict but never calls `_save_state()`.
If the process dies after `cmd_report` returns but before the user notes the output,
`investigation.json` still says `"status": "active"`. On resume, `--status` would
show an active investigation that was already reported. Minor: `--report` is
idempotent.

## Hidden Assumptions

1. **AI respects `force_terminate`.** Hard stops are response-level recommendations.
   The system relies on the AI to voluntarily stop calling `--step`. There is no
   mechanical enforcement. (P0-6)

2. **candidate IDs correspond to current graph state.** Enforced by `_save_candidates`
   after state save and `cmd_status` saving candidates. Crash between state+candidate
   saves leaves consistent state (state saved first, candidates may be stale but
   never ahead).

3. **Graph writes are atomic.** `investigation.json`, `graph.json`, `turn_NNN.json`,
   `candidates.json` all use `.tmp → rename`. `SUMMARY.md` does NOT — appended
   in-place (P1-5, cosmetic).

4. **Tool binaries are in PATH.** `runtime.py` returns `"tool_not_found"` if missing,
   but the registry doesn't validate binary existence at registration time.

5. **Parser output format is stable.** If a tool changes its output format, the
   parser silently returns zero entities (now surfaced via `parse_errors` in P1-2 fix).

6. **CLI constraints override stored constraints.** `{**stored, **cli}` merge in
   `cmd_step` means the AI can escalate its own privileges (set `dangerous_tools_enabled: true`)
   by passing it in a `--step` call. By design — the AI is the decision-maker.

## Autonomy Check

### 1. Is candidate generation genuinely dynamic?
**YES.** `generate_candidates()` iterates all graph nodes × all matching tools,
scores each, prunes to top-k. The candidate list changes with every graph mutation.
Different inputs produce different candidate sets (verified: email-only, username-only,
domain-only, NL mixed).

### 2. Can AI meaningfully override ranking?
**YES.** The AI selects any `action_id` from the candidate list regardless of rank.
`override_reasoning` field exists for documenting deviations. Tested: AI can pick
the lowest-ranked candidate.

**BUT:** The override is only meaningful if the AI has a REASON to override. The
scoring formula creates systematic bias (email tools > username tools). A weak model
that always picks `candidates[0]` would follow a deterministic path. The AI adds
value when it recognizes "confirmed username should be investigated before
unconfirmed email hypothesis."

### 3. If a weak model always picks rank #1, does the system degrade into a fixed pipeline?
**YES — partially.** The scoring formula is deterministic given graph state.
A model that always picks the top-ranked candidate would follow:
1. Email tools (holehe/h8mail) on any email entity → highest base_weight
2. Domain tools (theHarvester) on any domain
3. Username tools (maigret) on usernames
4. Hypothesis expansion when exhausted

This is a REASONABLE default strategy — not a bug. The scoring encodes the
SKILL.md priority rules (information density ordering). The system degrades
into a sensible heuristic pipeline, not a broken one. A strong model improves
on this by recognizing context-specific overrides.

## 6-Hour Unattended Trust

**NO — one blocker remains.**

P0-6: Hard stops are advisory. An AI that ignores `force_terminate` can loop
indefinitely. `consecutive_zero_yield` provides partial protection (3 zero-yield
turns → force terminate), but if each turn finds even 1 entity, the investigation
continues past max_depth and time_budget.

**What would change the answer to YES:**
Add the P0-6 pre-execution guard. With that guard, `cmd_step` rejects execution
after hard stops trigger. The 4 hard stops (no_candidates, max_depth, time_budget,
consecutive_zero_yield) become mechanically enforced, not advisory. The investigation
CANNOT exceed its bounds regardless of AI behavior.

---

# V2 Expansion — 2026-06-26

## V2 Tool Catalog

| Tool | Class | Entity In | Entity Out | Active | Timeout | Priority |
|------|-------|-----------|------------|--------|---------|----------|
| holehe | email_service_mapping | email | service | No | 120s | 0.90 |
| h8mail | breach_lookup | email | breach | No | 60s | 0.85 |
| maigret | username_enumeration | username | service | No | 300s | 0.90 |
| theHarvester | domain_harvesting | domain,email | email,domain,ip | No | 120s | 0.80 |
| **nmap** | network_scanning | ip,domain | ip,service,port | **Yes** | 300s | 0.75 |
| **amass** | subdomain_enumeration | domain | domain,ip | **Yes** | 300s | 0.70 |
| **hashcat** | password_cracking | hash | credential | **Yes** | 600s | 0.30 |
| **hydra** | online_brute_force | service | credential | **Yes** | 300s | 0.25 |
| **gobuster** | directory_busting | url | url | **Yes** | 300s | 0.35 |

All tools: `dangerous=False` (user directive — full access, no gates needed).
Safety gate code in `runtime.py:59` preserved but never triggered.

## MCP Server Architecture

```
MCP Client (Claude Code)  →  Unix Socket (~/.ai_osint_hub/mcp.sock)
                                    │
                              uvicorn + SSE transport
                                    │
                           FastMCP (mcp.server.fastmcp)
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
              osint_init      osint_step       osint_report
                    │          osint_status          │
                    └───────────────┼───────────────┘
                                    │
                           hub.orchestrate.cmd_*()
                                    │
                          (same as CLI path)
```

**Tools exposed:** osint_init, osint_step, osint_status, osint_report
**Transport:** SSE over HTTP on Unix domain socket
**Library:** mcp (PyPI) 1.28.1 — FastMCP with Starlette ASGI app

CLI and MCP share state — mix and match freely. Both call the same `cmd_*` functions.

## Round 7 Bug Fixes

| Bug | Fix |
|-----|-----|
| P1-9 | Time budget now computed in hypothesis_expand branch (was `elapsed=0`) |
| P1-10 | Tool stderr persisted to `raw/{tool}_{turn}_stderr.txt` |
| P1-12 | `deduplicate()` uses origin-preserving metadata merge |
| P1-13 | `_already_investigated()` uses equality check, not substring |

## Current File Counts

| Module | Lines | Notes |
|--------|-------|-------|
| `orchestrate.py` | ~880 | Controller loop, state persistence, CLI dispatch, lock, crash resilience |
| `registry.py` | ~290 | 9 ToolMeta entries, 10 tool classes, entity→tool discovery |
| `cooking.py` | ~480 | NL parsing, username gen, dedup (origin-safe), hypothesis expand |
| `graph/memory.py` | ~340 | Dict adjacency, origin-preserving merge, relationship dispatch |
| `candidates.py` | ~390 | 5-factor scoring, 4-stage pruning, top-k diversity, equality dedup |
| `evaluate.py` | ~175 | 4 hard stops, 4 soft stops, completeness heuristic |
| `runtime.py` | ~143 | Subprocess execution, safety gate |
| `mcp_server.py` | ~120 | FastMCP server, 4 MCP tools, Unix socket |
| Parsers (9) | ~560 | V1: holehe/maigret/h8mail/theHarvester; V2: nmap/amass/hashcat/hydra/gobuster |
