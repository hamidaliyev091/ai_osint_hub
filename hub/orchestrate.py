"""Controller loop — the central orchestrator for autonomous investigation.

Entry points:
  python3 -m hub.orchestrate --init   '{"raw_input":"...","constraints":{}}'
  python3 -m hub.orchestrate --step   '{"target_id":"...","selected_action_id":"act_000"}'
  python3 -m hub.orchestrate --status '{"target_id":"..."}'
  python3 -m hub.orchestrate --report '{"target_id":"..."}'

The orchestrator wires together all modules. It does NOT decide what to do.
The AI decides. The orchestrator handles mechanical work.
"""

import json
import os
import sys
import time
import fcntl
import errno
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

from hub.graph.memory import (
    ExposureGraph, link_person_to_username, link_email_to_service,
    link_email_to_breach, link_username_to_email, ingest_entity,
)
from hub.registry import get_tool, is_dangerous, resolve, export_catalog, list_tools
from hub.cooking import (
    parse_raw_input, generate_usernames, infer_emails,
    expand_hypotheses, deduplicate, score_confidence, CONFIDENCE,
    extract_emails, extract_domains,
)
from hub.executor.runtime import execute as run_tool, ExecutionResult
from hub.planner.candidates import generate_candidates
from hub.planner.evaluate import (
    check_hard_stops, check_soft_stops, compute_completeness,
)

# State root
STATE_ROOT = "/tmp/ai_osint_hub/state"
LOCK_TIMEOUT_S = 10  # Max wait for investigation lock

# Allowlisted virtual actions — only these bypass the runtime safety gate (P1-7)
VIRTUAL_ACTIONS = {"_hypothesis_expand"}


@contextmanager
def _investigation_lock(target_id: str):
    """Acquire exclusive lock on an investigation to prevent concurrent --step calls.

    Uses fcntl.flock on a .lock file in the case directory.
    Raises OSError if lock cannot be acquired within LOCK_TIMEOUT_S.
    """
    lock_dir = os.path.join(STATE_ROOT, target_id)
    os.makedirs(lock_dir, exist_ok=True)
    lock_path = os.path.join(lock_dir, ".lock")
    lock_fd = None
    try:
        lock_fd = open(lock_path, "w")
        deadline = time.monotonic() + LOCK_TIMEOUT_S
        while True:
            try:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno != errno.EAGAIN:
                    raise
                if time.monotonic() > deadline:
                    raise OSError(
                        errno.EAGAIN,
                        f"Investigation '{target_id}' is locked by another process "
                        f"(timed out after {LOCK_TIMEOUT_S}s)",
                    )
                time.sleep(0.1)
        yield
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_fd.close()


# ── Parser Dispatch (dynamic — P2-3) ────────────────────
# Parsers are loaded from registry parser paths on first use.
# Adding a new tool only requires: (1) registry entry, (2) parser module.
# No orchestrator edits needed.

_PARSER_CACHE: dict[str, callable] = {}

def _get_parser(tool_name: str):
    """Dynamically import and cache a parser by tool name."""
    if tool_name in _PARSER_CACHE:
        return _PARSER_CACHE[tool_name]
    meta = get_tool(tool_name)
    if meta is None or not meta.parser:
        return None
    # parser format: "hub.executor.parsers.holehe:parse"
    module_path, func_name = meta.parser.split(":")
    import importlib
    module = importlib.import_module(module_path)
    parser_fn = getattr(module, func_name)
    _PARSER_CACHE[tool_name] = parser_fn
    return parser_fn


# ── Helpers ───────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_elapsed(history: list[dict], current_ts: str) -> float:
    """Compute elapsed seconds from first turn timestamp to current."""
    if not history:
        return 0.0
    try:
        first_ts = history[0].get("timestamp", current_ts)
        start = datetime.fromisoformat(first_ts)
        now = datetime.fromisoformat(current_ts)
        return (now - start).total_seconds()
    except (ValueError, TypeError) as e:
        import sys
        print(f"[WARN] _compute_elapsed: bad timestamp format — {e}. "
              f"Time budget may be inaccurate.", file=sys.stderr)
        return 0.0


def _load_state(target_id: str) -> Optional[dict]:
    """Load investigation state from disk.

    Returns dict with keys {investigation, graph, history} on success,
    None if the investigation doesn't exist, or
    {"_corrupt": True, "file": str, "error": str} if state files are corrupted.
    """
    inv_path = os.path.join(STATE_ROOT, target_id, "investigation.json")
    graph_path = os.path.join(STATE_ROOT, target_id, "graph.json")
    if not os.path.exists(inv_path) or not os.path.exists(graph_path):
        return None

    try:
        with open(inv_path) as f:
            investigation = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return {"_corrupt": True, "file": inv_path,
                "error": f"investigation.json: {type(e).__name__}: {str(e)[:200]}"}

    try:
        with open(graph_path) as f:
            graph_data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return {"_corrupt": True, "file": graph_path,
                "error": f"graph.json: {type(e).__name__}: {str(e)[:200]}"}

    try:
        graph = ExposureGraph.from_dict(graph_data)
    except Exception as e:
        return {"_corrupt": True, "file": graph_path,
                "error": f"graph.json deserialization: {type(e).__name__}: {str(e)[:200]}"}

    # Load turn history
    turns = []
    turn_dir = os.path.join(STATE_ROOT, target_id)
    i = 1
    while True:
        turn_path = os.path.join(turn_dir, f"turn_{i:03d}.json")
        if not os.path.exists(turn_path):
            break
        try:
            with open(turn_path) as f:
                turns.append(json.load(f))
        except (json.JSONDecodeError, OSError):
            # Corrupt turn file — skip it, don't fail the whole load
            pass
        i += 1

    return {
        "investigation": investigation,
        "graph": graph,
        "history": turns,
    }


def _save_state(target_id: str, investigation: dict, graph: ExposureGraph,
                turn_record: dict = None) -> bool:
    """Persist state to disk atomically.

    Returns True on success, False on failure (disk full, permission denied, etc.).
    On failure, the old files are preserved (atomic rename guarantee).
    Callers must check the return value and bail out with a clean error.
    """
    inv_dir = os.path.join(STATE_ROOT, target_id)
    try:
        os.makedirs(inv_dir, exist_ok=True)
        os.makedirs(os.path.join(inv_dir, "raw"), exist_ok=True)
    except OSError:
        return False

    # Atomic writes: tmp → rename
    inv_path = os.path.join(inv_dir, "investigation.json")
    tmp = inv_path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(investigation, f, indent=2, default=str)
        os.rename(tmp, inv_path)
    except OSError:
        return False

    graph_path = os.path.join(inv_dir, "graph.json")
    tmp = graph_path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(graph.to_dict(), f, indent=2, default=str)
        os.rename(tmp, graph_path)
    except OSError:
        return False

    if turn_record:
        turn_path = os.path.join(inv_dir, f"turn_{turn_record['turn_id']:03d}.json")
        tmp = turn_path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(turn_record, f, indent=2, default=str)
            os.rename(tmp, turn_path)
        except OSError:
            return False

    # Append human-readable summary (atomic — P1-5)
    if turn_record:
        summary_path = os.path.join(inv_dir, "SUMMARY.md")
        try:
            # Read existing content
            existing = ""
            if os.path.exists(summary_path):
                with open(summary_path) as f:
                    existing = f.read()
            # Append new entry
            action = turn_record.get("action", {})
            result = turn_record.get("result", {})
            new_entry = (
                f"\n## Turn {turn_record['turn_id']} — {turn_record.get('timestamp','')}\n"
                f"**Action:** {action.get('tool','')} with {action.get('params',{})}\n"
                f"**Result:** {result.get('status','')}, "
                f"{result.get('new_entity_count',0)} new entities\n"
                f"**State:** {investigation.get('total_nodes',0)} nodes, "
                f"{investigation.get('total_edges',0)} edges, "
                f"completeness {investigation.get('completeness',0):.2f}\n"
            )
            # Atomic write: tmp → rename
            tmp = summary_path + ".tmp"
            with open(tmp, "w") as f:
                f.write(existing + new_entry)
            os.rename(tmp, summary_path)
        except OSError:
            pass  # SUMMARY.md is cosmetic — never fail for it

    return True


# ── Candidate Persistence ─────────────────────────────────

def _save_candidates(target_id: str, candidates):
    """Persist candidate snapshot for --step validation."""
    inv_dir = os.path.join(STATE_ROOT, target_id)
    os.makedirs(inv_dir, exist_ok=True)
    path = os.path.join(inv_dir, "candidates.json")
    tmp = path + ".tmp"
    data = {c.action_id: {"tool": c.tool, "params": c.params,
                          "entity_type": c.entity_type,
                          "entity_target": c.entity_target}
            for c in candidates}
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, default=str)
    os.rename(tmp, path)


def _load_candidates(target_id: str) -> dict:
    """Load stored candidate snapshot. Returns {action_id: {tool, params, ...}}."""
    path = os.path.join(STATE_ROOT, target_id, "candidates.json")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def _lookup_action(target_id: str, selected_action_id: str) -> Optional[dict]:
    """Look up a candidate action by ID. Returns {tool, params, ...} or None."""
    candidates = _load_candidates(target_id)
    return candidates.get(selected_action_id)


# ── CLI Entry Points ──────────────────────────────────────

def cmd_init(raw_input: str, constraints: dict = None) -> dict:
    """Initialize a new investigation.

    Returns structured state for AI evaluation.
    """
    if constraints is None:
        constraints = {}

    target_id = constraints.get("target_id",
                                 f"case_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
    timestamp = _now_iso()

    # Parse raw input
    parsed = parse_raw_input(raw_input)

    # Generate hypotheses
    persons = parsed.get("persons", [])
    suffixes = parsed.get("numeric_suffixes", [])
    interests = parsed.get("interests", [])
    associations = parsed.get("associations", [])
    parsed_emails = parsed.get("emails", [])
    parsed_domains = parsed.get("domains", [])
    parsed_usernames = parsed.get("usernames", [])

    usernames = generate_usernames(persons, suffixes, interests)

    # For associates, also generate their usernames
    assoc_persons = [{"name": a["name"]} for a in associations]
    for ap in assoc_persons:
        usernames.extend(generate_usernames([ap], suffixes, interests))

    usernames = sorted(set(usernames))
    email_domains = parsed_domains if parsed_domains else None
    # Email inference strategy:
    # - If user already gave explicit emails, don't generate speculative ones from
    #   random words in the text (e.g., "cybersecurity@gmail.com" from "cybersecurity").
    # - Only generate emails from person-name-derived usernames (e.g., "hamid@gmail.com"
    #   from person "Hamid") — these are actually useful.
    # - If no explicit emails provided, fall back to inferring from all sources.
    if parsed_emails:
        # User gave real emails — only generate from person-name usernames
        emails_to_infer = [u for u in usernames if u not in parsed_usernames][:5]
    else:
        # No explicit emails — infer from parsed words + person names
        emails_to_infer = list(parsed_usernames[:5])
        gen_for_email = [u for u in usernames if u not in emails_to_infer][:5]
        emails_to_infer.extend(gen_for_email)
    inferred_emails = infer_emails(emails_to_infer[:10], email_domains) if emails_to_infer else []

    # Seed the graph
    graph = ExposureGraph()

    # Add persons (origin: raw_input)
    person_ids = []
    for p in persons:
        pid, _ = graph.add_node("person", p["name"],
                            confidence=p.get("confidence", CONFIDENCE["person_raw_input"]),
                            source="raw_input",
                            metadata={"origin": "raw_input"},
                            timestamp=timestamp)
        person_ids.append(pid)

    # Add associates as persons (origin: raw_input)
    for a in associations:
        graph.add_node("person", a["name"],
                      confidence=a.get("confidence", CONFIDENCE["associate_raw_input"]),
                      source="raw_input",
                      metadata={"relation": a.get("relation", ""), "origin": "raw_input"},
                      timestamp=timestamp)

    # Add parsed emails (origin: raw_input)
    for email in parsed_emails:
        eid, _ = graph.add_node("email", email, confidence=CONFIDENCE["parsed_email"],
                            source="raw_input",
                            metadata={"origin": "raw_input"},
                            timestamp=timestamp)
        for pid in person_ids:
            link_username_to_email(graph, pid, eid, confidence=0.7, source_tool="raw_input")

    # Add parsed domains (origin: raw_input)
    for domain in parsed_domains:
        graph.add_node("domain", domain, confidence=CONFIDENCE["parsed_domain"],
                      source="raw_input",
                      metadata={"origin": "raw_input"},
                      timestamp=timestamp)

    # Add parsed usernames (origin: raw_input)
    for u in parsed_usernames:
        uid, _ = graph.add_node("username", u, confidence=CONFIDENCE["parsed_username"],
                            source="raw_input",
                            metadata={"origin": "raw_input"},
                            timestamp=timestamp)
        for pid in person_ids:
            link_person_to_username(graph, pid, uid, confidence=0.7,
                                    source_tool="raw_input")

    # Add generated usernames (origin: hypothesis_expansion)
    # Direct person names (e.g., "hazi" from "Hazi") get higher confidence
    # than generated variants (e.g., "hazi23", "23hazi")
    person_first_names = {p["name"].lower().split()[0] for p in persons}
    for u in usernames[:30]:
        is_direct = u.lower() in person_first_names
        conf = 0.60 if is_direct else CONFIDENCE["generated_username"]
        uid, _ = graph.add_node("username", u, confidence=conf,
                            source="hypothesis_generation",
                            metadata={"origin": "hypothesis_expansion"},
                            timestamp=timestamp)
        for pid in person_ids:
            link_person_to_username(graph, pid, uid, confidence=conf * 0.7,
                                    source_tool="hypothesis_generation")

    # Add inferred emails with differentiated confidence
    # Emails from direct usernames get higher confidence
    for email in inferred_emails:
        prefix = email.split("@")[0] if "@" in email else ""
        is_direct = prefix.lower() in person_first_names
        conf = 0.50 if is_direct else CONFIDENCE["generated_email"]
        graph.add_node("email", email, confidence=conf,
                      source="hypothesis_generation",
                      metadata={"origin": "hypothesis_expansion"},
                      timestamp=timestamp)

    # Generate initial candidates
    candidates = generate_candidates(graph, [], allow_dangerous=False)
    completeness = compute_completeness(graph, [])

    # Save state
    investigation = {
        "target_id": target_id,
        "created_at": timestamp,
        "updated_at": timestamp,
        "status": "active",
        "raw_input": raw_input,
        "constraints": constraints,
        "turn_count": 0,
        "total_nodes": graph.summary()["total_nodes"],
        "total_edges": graph.summary()["total_edges"],
        "completeness": completeness,
    }
    if not _save_state(target_id, investigation, graph):
        return {"status": "error", "errors": [
            f"Failed to persist state for '{target_id}'. Disk may be full or unwritable."]}

    # Persist candidate snapshot for --step validation
    _save_candidates(target_id, candidates)

    return {
        "status": "initialized",
        "target_id": target_id,
        "state_path": os.path.join(STATE_ROOT, target_id),
        "parsed_input": {
            "persons": persons,
            "interests": interests,
            "numeric_suffixes": suffixes,
            "associations": associations,
            "emails_found": parsed_emails,
            "domains_found": parsed_domains,
        },
        "hypotheses": {
            "generated_usernames": usernames[:20],  # Truncate for display
            "generated_usernames_count": len(usernames),
            "generated_emails": inferred_emails[:20],
            "generated_emails_count": len(inferred_emails),
        },
        "candidate_actions": _serialize_candidates(candidates),
        "candidate_count": len(candidates),
        "graph_summary": graph.summary(),
        "completeness": completeness,
        "available_tools": [
            f"{t}:{','.join(get_tool(t).entity_input)}"
            for t in list_tools()
        ],
    }


def cmd_step(target_id: str, selected_action_id: str = None,
             action: dict = None, constraints: dict = None) -> dict:
    """Execute one AI-decided action and update state.

    Primary path: selected_action_id — validated against stored candidate snapshot.
    Fallback: raw action dict — validated against stored candidate snapshot by tool+params match.
    """
    if constraints is None:
        constraints = {}

    # Acquire investigation lock BEFORE loading state to prevent TOCTOU race.
    # P0-7: Without this lock, two concurrent --step calls on the same target_id
    # read the same initial state and produce turn collisions with silent data loss.
    try:
        with _investigation_lock(target_id):
            state = _load_state(target_id)
            if state is None:
                return {"status": "error", "errors": [f"Investigation not found: {target_id}"]}
            if state.get("_corrupt"):
                return {"status": "error", "errors": [
                    f"State file corrupted for '{target_id}': {state.get('error', 'unknown')}. "
                    f"Restore from backup or re-init."]}
            return _cmd_step_locked(target_id, selected_action_id, action, constraints, state)
    except OSError as e:
        if e.errno == errno.EAGAIN:
            return {
                "status": "error",
                "errors": [f"Investigation '{target_id}' is locked by another process. "
                           f"Wait for it to complete and retry."],
            }
        raise


def _cmd_step_locked(target_id: str, selected_action_id: str,
                     action: dict, constraints: dict, state: dict) -> dict:
    """Body of cmd_step — called inside _investigation_lock with state already loaded."""

    # ── Pre-execution gate: hard stops are mechanically enforced ──
    investigation = state["investigation"]
    history = state["history"]

    # Reject if investigation already terminated
    if investigation.get("status") in ("terminated", "complete"):
        return {
            "status": "error",
            "errors": [f"Investigation '{target_id}' is already {investigation['status']}. "
                       f"No further steps allowed. Use --report for final output."],
        }

    # Reject if previous turn triggered hard stops — prevents ignore-loop
    if history:
        last_hard_stops = history[-1].get("hard_stops", [])
        if any(s.get("triggered") for s in last_hard_stops):
            triggered_types = [s["type"] for s in last_hard_stops if s.get("triggered")]
            return {
                "status": "error",
                "errors": [f"Investigation reached hard stop(s): {', '.join(triggered_types)}. "
                           f"No further steps allowed. Use --report for final output."],
            }

    # Merge: stored investigation constraints take precedence, CLI overrides
    stored_constraints = state["investigation"].get("constraints", {})
    if constraints:
        constraints = {**stored_constraints, **constraints}
    else:
        constraints = stored_constraints
    if selected_action_id:
        stored = _lookup_action(target_id, selected_action_id)
        if stored is None:
            return {
                "status": "error",
                "errors": [f"Invalid action_id '{selected_action_id}'. "
                           f"It may be stale — re-run --status for current candidates."],
            }
        tool_name = stored["tool"]
        params = stored["params"]
        entity_type = stored.get("entity_type", "")
        rationale = f"[action_id: {selected_action_id}]"
    elif action:
        # Fallback: validate raw action against stored candidates
        tool_name = action.get("tool", "")
        params = action.get("params", {})
        rationale = action.get("rationale", "")
        # Validate that this action exists in the stored candidate list
        stored = _load_candidates(target_id)
        found = False
        for aid, s in stored.items():
            if s["tool"] == tool_name and s["params"] == params:
                found = True
                break
        if not found:
            return {
                "status": "error",
                "errors": [f"Raw action {tool_name}:{params} not found in candidate list. "
                           f"Use selected_action_id from --status or --init response."],
            }
    else:
        return {"status": "error", "errors": ["No selected_action_id or action provided"]}

    graph = state["graph"]
    turn_count = investigation["turn_count"] + 1
    timestamp = _now_iso()

    # Build action dict for turn record
    action = {"tool": tool_name, "params": params, "rationale": rationale,
              "entity_type": entity_type if selected_action_id else action.get("entity_type", "")}

    allow_dangerous = constraints.get("dangerous_tools_enabled", False)

    # Check safety
    if is_dangerous(tool_name) and not allow_dangerous:
        return {
            "status": "blocked",
            "turn": turn_count,
            "errors": [f"Tool '{tool_name}' requires explicit authorization"],
            "stop_recommendation": "continue",
        }

    # Handle virtual actions
    if tool_name in VIRTUAL_ACTIONS:
        # P1-7: Virtual action safety gate. _hypothesis_expand is the only
        # virtual action and is safe (no subprocess, no network, no target interaction).
        # Future virtual actions MUST be registered in VIRTUAL_ACTIONS allowlist
        # or route through the same dangerous/active gate as real tools.
        all_entities = [
            {"type": n.type, "value": n.value, "confidence": n.confidence,
             "source": s, "metadata": n.metadata}
            for n in graph.nodes.values()
            for s in n.sources
        ]
        new_hypotheses = expand_hypotheses(all_entities, graph)
        new_entities_created = 0
        for h in new_hypotheses:
            _, is_new = graph.add_node(
                h["type"], h["value"], confidence=h["confidence"],
                source=h.get("source", "hypothesis_expansion"),
                metadata=h.get("metadata", {}),
                timestamp=timestamp,
            )
            if is_new:
                new_entities_created += 1

        turn_record = {
            "turn_id": turn_count, "timestamp": timestamp,
            "action": action,
            "result": {"status": "success", "new_entity_count": new_entities_created,
                       "duration_ms": 0},
            "hard_stops": [], "soft_stops": [],
        }

        investigation["turn_count"] = turn_count
        investigation["updated_at"] = timestamp
        investigation["total_nodes"] = graph.summary()["total_nodes"]
        investigation["total_edges"] = graph.summary()["total_edges"]
        completeness = compute_completeness(graph, history + [turn_record])
        investigation["completeness"] = completeness

        candidates = generate_candidates(graph, history + [turn_record])
        elapsed = _compute_elapsed(history, timestamp)
        hard_stops = check_hard_stops(graph, constraints, turn_count,
                                      elapsed, candidates, history + [turn_record])
        soft_stops = check_soft_stops(graph, history + [turn_record],
                                      candidates, turn_count, completeness)
        turn_record["hard_stops"] = hard_stops
        turn_record["soft_stops"] = soft_stops
        turn_record["candidates_before_count"] = len(candidates)

        if not _save_state(target_id, investigation, graph, turn_record):
            return {"status": "error", "errors": [
                f"Failed to persist state for '{target_id}'. Disk may be full or unwritable."]}
        _save_candidates(target_id, candidates)

        return _build_step_response(target_id, turn_count, turn_record,
                                     graph, candidates, hard_stops, soft_stops,
                                     completeness)

    # Execute real tool
    result: ExecutionResult = run_tool(
        tool_name, params,
        allow_dangerous=allow_dangerous,
    )

    # Parse output
    new_entities = []
    parse_errors = []
    if result.status == "success":
        parser = _get_parser(tool_name)
        if parser:
            target = str(list(params.values())[0]) if params else ""
            try:
                parsed = parser(result.raw_stdout, target)
                new_entities = parsed
            except Exception as e:
                parse_errors.append(
                    f"Parser '{tool_name}' failed on output: {type(e).__name__}: {str(e)[:200]}"
                )

    # Cook entities: normalize + dedup
    cleaned = deduplicate(new_entities)
    for entity in cleaned:
        entity["source"] = entity.get("source", "tool_output")
        if not entity.get("sources"):
            entity["sources"] = [f"{tool_name}:{list(params.values())[0] if params else ''}"]

    # Ingest into graph (relationship dispatch handled by graph module)
    new_count = 0
    for entity in cleaned:
        _, is_new = ingest_entity(graph, entity, params, tool_name, timestamp)
        if is_new:
            new_count += 1

    # Expand hypotheses from new entities
    if new_entities:
        expanded = expand_hypotheses(cleaned, graph)
        for h in expanded:
            _, is_new = graph.add_node(h["type"], h["value"], confidence=h["confidence"],
                                       source=h.get("source", "hypothesis_expansion"),
                                       metadata=h.get("metadata", {}),
                                       timestamp=timestamp)
            if is_new:
                new_count += 1

    # Save raw output (atomic write — P1-18)
    raw_dir = os.path.join(STATE_ROOT, target_id, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    raw_path = os.path.join(raw_dir, f"{tool_name}_{turn_count:03d}.txt")
    raw_tmp = raw_path + ".tmp"
    try:
        with open(raw_tmp, "w") as f:
            f.write(result.raw_stdout)
        os.rename(raw_tmp, raw_path)
    except OSError:
        pass  # Raw output is non-critical — never fail a turn for it

    # Save stderr (P1-10: previously captured but never persisted)
    if result.raw_stderr:
        stderr_path = os.path.join(raw_dir, f"{tool_name}_{turn_count:03d}_stderr.txt")
        stderr_tmp = stderr_path + ".tmp"
        try:
            with open(stderr_tmp, "w") as f:
                f.write(result.raw_stderr)
            os.rename(stderr_tmp, stderr_path)
        except OSError:
            pass

    # Build turn record
    turn_record = {
        "turn_id": turn_count, "timestamp": timestamp,
        "action": action,
        "result": {
            "status": result.status, "new_entity_count": new_count,
            "duration_ms": result.duration_ms,
            "parse_errors": parse_errors,
        },
        "candidates_before_count": 0,  # Filled below
        "hard_stops": [], "soft_stops": [],
    }

    # Update investigation
    investigation["turn_count"] = turn_count
    investigation["updated_at"] = timestamp
    investigation["total_nodes"] = graph.summary()["total_nodes"]
    investigation["total_edges"] = graph.summary()["total_edges"]
    completeness = compute_completeness(graph, history + [turn_record])
    investigation["completeness"] = completeness

    # Evaluate stops — compute elapsed from turn timestamps
    updated_history = history + [turn_record]
    elapsed = _compute_elapsed(history, timestamp)
    candidates = generate_candidates(graph, updated_history,
                                     allow_dangerous=allow_dangerous)
    turn_record["candidates_before_count"] = len(candidates)
    hard_stops = check_hard_stops(graph, constraints, turn_count, elapsed,
                                   candidates, updated_history)
    soft_stops = check_soft_stops(graph, updated_history, candidates, turn_count,
                                  completeness)
    turn_record["hard_stops"] = hard_stops
    turn_record["soft_stops"] = soft_stops

    # Persist state BEFORE candidates — crash after state save is recoverable.
    # Candidates saved last so they're never ahead of graph state.
    if not _save_state(target_id, investigation, graph, turn_record):
        return {"status": "error", "errors": [
            f"Failed to persist state for '{target_id}'. Disk may be full or unwritable."]}
    _save_candidates(target_id, candidates)

    return _build_step_response(target_id, turn_count, turn_record,
                                 graph, candidates, hard_stops, soft_stops,
                                 completeness)


def cmd_status(target_id: str) -> dict:
    """Return current investigation state for resume."""
    state = _load_state(target_id)
    if state is None:
        return {"status": "error", "errors": [f"Investigation not found: {target_id}"]}
    if state.get("_corrupt"):
        return {"status": "error", "errors": [
            f"State file corrupted for '{target_id}': {state.get('error', 'unknown')}. "
            f"Restore from backup or re-init."]}

    graph = state["graph"]
    history = state["history"]
    investigation = state["investigation"]

    candidates = generate_candidates(graph, history)
    _save_candidates(target_id, candidates)
    completeness = investigation.get("completeness",
                                      compute_completeness(graph, history))

    return {
        "status": "active",
        "target_id": target_id,
        "investigation": investigation,
        "graph_summary": graph.summary(),
        "candidate_actions": _serialize_candidates(candidates),
        "candidate_count": len(candidates),
        "completeness": completeness,
        "turn_count": investigation["turn_count"],
        "last_3_turns": [
            {"turn_id": t["turn_id"], "action": t.get("action", {}).get("tool", ""),
             "new_entities": t.get("result", {}).get("new_entity_count", 0)}
            for t in history[-3:]
        ],
    }


def cmd_report(target_id: str) -> dict:
    """Generate final investigation report."""
    state = _load_state(target_id)
    if state is None:
        return {"status": "error", "errors": [f"Investigation not found: {target_id}"]}
    if state.get("_corrupt"):
        return {"status": "error", "errors": [
            f"State file corrupted for '{target_id}': {state.get('error', 'unknown')}. "
            f"Restore from backup or re-init."]}

    graph = state["graph"]
    history = state["history"]
    investigation = state["investigation"]

    # Build Markdown report
    lines = [
        f"# Investigation Summary: {target_id}",
        "",
        f"**Created:** {investigation.get('created_at','')}",
        f"**Turns:** {investigation.get('turn_count',0)}",
        f"**Status:** {investigation.get('status','')}",
        f"**Completeness:** {investigation.get('completeness',0):.2f}",
        "",
        "## Discovered Entities",
        "",
    ]

    total = graph.summary()
    lines.append(f"**Total:** {total['total_nodes']} nodes, {total['total_edges']} edges")
    lines.append("")

    for etype in ["person", "email", "username", "domain", "ip", "phone",
                   "service", "breach", "credential"]:
        nodes = graph.get_nodes_by_type(etype)
        if nodes:
            lines.append(f"### {etype.capitalize()}s ({len(nodes)})")
            for n in nodes[:30]:  # Cap per type
                conf_bar = "█" * int(n.confidence * 10) + "░" * (10 - int(n.confidence * 10))
                extras = ""
                if n.metadata:
                    extras = f" — {json.dumps(n.metadata, default=str)[:80]}"
                lines.append(f"- `{n.value}` [{conf_bar}] {n.confidence:.2f}{extras}")
            if len(nodes) > 30:
                lines.append(f"  *... and {len(nodes)-30} more*")
            lines.append("")

    lines.append("## Relationships")
    lines.append("")
    edge_types = {}
    for e in graph.edges:
        edge_types[e.type] = edge_types.get(e.type, 0) + 1
    for etype, count in sorted(edge_types.items()):
        lines.append(f"- {etype}: {count}")
    lines.append("")

    # Recommendations
    lines.append("## Recommendations")
    lines.append("")

    breach_nodes = graph.get_nodes_by_type("breach")
    if breach_nodes:
        lines.append("### ⚠ Credential Exposure")
        for b in breach_nodes:
            lines.append(f"- Email exposed in **{b.value}** breach")
            if b.metadata.get("credentials_exposed"):
                lines.append(f"  - ⚠ **Password hash exposed** — rotate immediately")
        lines.append("")

    service_nodes = graph.get_nodes_by_type("service")
    registered_count = sum(1 for s in service_nodes
                          if s.metadata.get("registered", False))
    if registered_count > 0:
        lines.append("### Account Hygiene")
        lines.append(f"- {registered_count} online services mapped")
        lines.append("- Enable 2FA on all active accounts")
        lines.append("- Remove unused/abandoned accounts")
        lines.append("")

    lines.append("### General")
    lines.append("- Conduct regular breach monitoring")
    lines.append("- Consider email alias strategy for service separation")
    lines.append("")

    report_md = "\n".join(lines)

    # Determine final status based on termination reason
    if history:
        last_hard_stops = history[-1].get("hard_stops", [])
        if any(s.get("triggered") for s in last_hard_stops):
            investigation["status"] = "terminated"
        else:
            investigation["status"] = "complete"
    else:
        investigation["status"] = "complete"
    investigation["updated_at"] = _now_iso()
    # Persist the status change (P1-11: was in-memory only, now persisted)
    _save_state(target_id, investigation, graph)

    return {
        "status": "complete",
        "target_id": target_id,
        "report_md": report_md,
        "graph_summary": total,
    }


# ── Helpers ───────────────────────────────────────────────

def _serialize_candidates(candidates) -> list[dict]:
    """Serialize CandidateAction list to JSON-safe dicts."""
    result = []
    for c in candidates:
        result.append({
            "action_id": c.action_id,
            "tool": c.tool,
            "params": c.params,
            "entity_target": c.entity_target,
            "entity_type": c.entity_type,
            "entity_confidence": c.entity_confidence,
            "expected_yield": c.expected_yield,
            "score": c.score.total,
            "score_breakdown": {
                "base_weight": c.score.base_weight,
                "confidence_multiplier": c.score.confidence_multiplier,
                "unexplored_bonus": c.score.unexplored_bonus,
                "redundancy_penalty": c.score.redundancy_penalty,
                "cost_factor": c.score.cost_factor,
            },
            "tool_cost": c.tool_cost,
            "dangerous": c.dangerous,
            "active": c.active,
            "rationale": c.rationale,
        })
    return result


def _build_step_response(target_id: str, turn_count: int, turn_record: dict,
                          graph: ExposureGraph, candidates,
                          hard_stops: list, soft_stops: list,
                          completeness: float) -> dict:
    """Build the structured --step response."""
    # Determine stop recommendation
    if any(s.get("triggered", False) for s in hard_stops):
        stop_recommendation = "force_terminate"
    elif soft_stops:
        stop_recommendation = "consider_stop"
    else:
        stop_recommendation = "continue"

    # Collect new entities from this turn
    new_entity_count = turn_record.get("result", {}).get("new_entity_count", 0)

    result_data = turn_record.get("result", {})
    return {
        "turn": turn_count,
        "status": "completed",
        "action_taken": turn_record.get("action", {}),
        "execution_status": result_data.get("status", "unknown"),
        "new_entities_count": new_entity_count,
        "parse_errors": result_data.get("parse_errors", []),
        "duration_ms": result_data.get("duration_ms", 0),
        "graph_summary": graph.summary(),
        "candidate_actions": _serialize_candidates(candidates),
        "candidate_count": len(candidates),
        "completeness": completeness,
        "hard_stops": hard_stops,
        "soft_stops": soft_stops,
        "stop_recommendation": stop_recommendation,
    }


# ── CLI Entry Point ───────────────────────────────────────

def main():
    """CLI dispatcher for python3 -m hub.orchestrate."""
    import argparse

    parser = argparse.ArgumentParser(prog="orchestrate")
    parser.add_argument("--init", type=str, default=None,
                        help="Initialize investigation: JSON {raw_input, constraints}")
    parser.add_argument("--step", type=str, default=None,
                        help="Execute one action: JSON {target_id, action}")
    parser.add_argument("--status", type=str, default=None,
                        help="Get investigation status: JSON {target_id}")
    parser.add_argument("--report", type=str, default=None,
                        help="Generate report: JSON {target_id}")

    args = parser.parse_args()

    if args.init:
        data = json.loads(args.init)
        result = cmd_init(data["raw_input"], data.get("constraints", {}))
    elif args.step:
        data = json.loads(args.step)
        result = cmd_step(
            data["target_id"],
            selected_action_id=data.get("selected_action_id"),
            action=data.get("action"),
            constraints=data.get("constraints", {}),
        )
    elif args.status:
        data = json.loads(args.status)
        result = cmd_status(data["target_id"])
    elif args.report:
        data = json.loads(args.report)
        result = cmd_report(data["target_id"])
    else:
        print(json.dumps({"status": "error", "errors": ["No command specified"]}))
        sys.exit(1)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
