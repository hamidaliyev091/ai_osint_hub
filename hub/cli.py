"""Command-line interface — ``python -m hub.cli`` (Spec 5).

Five operations with full parity to the MCP server:
    tools        live health check of installed binaries / python collectors
    investigate  autonomous investigation loop with explicit budgets
    step         execute exactly one hypothesis/pivot cycle
    graph        query entities, claims, contradictions, hypotheses, provenance
    report       evidence-cited Markdown or JSON dossier

All output is JSON when ``--json`` is passed, so the CLI is scriptable.
"""

from __future__ import annotations

import argparse
import inspect
import json
import socket
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any, Optional

from hub.bundle import BUNDLE_EXTENSION
from hub.service import InvestigationService

CLI_VERSION = "2.1.0"


def _configure_stdio() -> None:
    """Make Windows consoles tolerate the arbitrary Unicode found in OSINT data."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _is_error(payload: dict[str, Any]) -> bool:
    return payload.get("status") == "error"


def _print_actions(actions: list[dict[str, Any]], limit: int = 8) -> None:
    if not actions:
        print("  (no candidate pivots above the configured threshold)")
        return
    print(f"  {'action':10} {'tool':18} {'score':>7}  rationale")
    for action in actions[:limit]:
        score = action.get("score")
        score_text = f"{score:.4f}" if isinstance(score, (int, float)) else "n/a"
        print(f"  {action['action_id']:10} {str(action['tool']):18} {score_text:>7}  "
              f"{str(action.get('rationale', ''))[:100]}")


# ════════════════════════════════════════════════════════════════════════
# Command handlers
# ════════════════════════════════════════════════════════════════════════

def cmd_tools(service: InvestigationService, args) -> int:
    result = service.tools(refresh=args.refresh)
    if args.json:
        _print_json(result)
        return 0
    marker = "✅" if result["available"] == result["total"] else "⚠️"
    print(f"{marker} AI OSINT Hub — capability health: "
          f"{result['available']}/{result['total']} AVAILABLE · "
          f"auth-ready {result.get('auth_ready', result['available'])}/{result['total']}")
    print()
    print(result["table"])
    print()
    if result["missing_tools"]:
        print("❌ Missing (reported, never mocked): "
              + ", ".join(result["missing_tools"]))
        print("Run `python -m hub.cli doctor --provision` to install them.")
    else:
        print("✅ All declared capabilities are AVAILABLE and executable.")
    auth_blocked = result.get("auth_blocked_tools") or []
    if auth_blocked:
        print("🔑 Auth not configured (skipped by pivot planner): "
              + ", ".join(auth_blocked))
        print("   Configure with the Web UI API Keys drawer or "
              "`python -m hub.cli auth set <provider> <value>`.")
    return 0


def cmd_doctor(service: InvestigationService, args) -> int:
    """Verify (and optionally provision) the complete toolchain."""
    from hub.toolchain.doctor import format_doctor_report, run_doctor

    smoke = not getattr(args, "no_smoke", False)
    params = inspect.signature(run_doctor).parameters
    if "smoke" in params:
        result = run_doctor(provision=args.provision, smoke=smoke)
    else:
        result = run_doctor(provision=args.provision)
    if args.json:
        _print_json(result)
    else:
        print(format_doctor_report(result))
    if not smoke:
        return 0
    return 0 if result["available"] == result["total"] else 1


def cmd_auth(service: InvestigationService, args) -> int:
    """Credential status / update (never prints or accepts raw secrets in output)."""
    if args.auth_action == "status":
        payload = service.credentials()
        if args.json:
            _print_json(payload)
            return 0
        summary = payload["summary"]
        print(f"🔑 API credentials — {summary['configured']}/{summary['total']} "
              f"providers configured · vault: {payload['vault_path']}")
        print()
        print("| Provider | Status | Configured | Masked preview |")
        print("|----------|--------|------------|----------------|")
        for provider, info in payload["providers"].items():
            previews = ", ".join(
                f"{field['label']}: {field['masked'] or '—'}"
                for field in info["fields"].values()
            )
            print(f"| {provider} | {info['auth_status']} | "
                  f"{'✅' if info['configured'] else '—'} | {previews} |")
        print()
        print("Set keys with: python -m hub.cli auth set <provider> <value>")
        print("Censys: auth set censys <api_id> --censys-secret <api_secret>")
        return 0

    provider = args.provider
    value = args.value
    data: dict[str, str] = {}
    if provider == "github":
        data["github_token"] = value
    elif provider == "virustotal":
        data["virustotal_api_key"] = value
    elif provider == "shodan":
        data["shodan_api_key"] = value
    elif provider == "hunter":
        data["hunter_api_key"] = value
    elif provider == "censys":
        data["censys_api_id"] = value
        if args.censys_secret:
            data["censys_api_secret"] = args.censys_secret
        if args.censys_token:
            data["censys_token"] = args.censys_token
    payload = service.set_credentials(data)
    if args.json:
        _print_json(payload)
    else:
        label = provider
        info = payload["providers"].get(label, {})
        print(f"✅ Saved {label} credential "
              f"({info.get('auth_status', 'CONFIGURED')}); masked previews only.")
        print(f"   Vault: {service.credentials()['vault_path']}")
        print("   TheHarvester api-keys.yaml synced; tool auth statuses refreshed.")
    return 0


def _parse_structured_seeds(args) -> Optional[dict[str, Any]]:
    """Build the structured seed dict from CLI flags (Phase 8 multi-clue intake)."""
    data: dict[str, Any] = {}
    if getattr(args, "name", None):
        data["name"] = args.name
    if getattr(args, "org", None):
        data["organizations"] = [args.org]
    if getattr(args, "location", None):
        data["locations"] = [args.location]
    for attribute, key in (("username", "usernames"), ("email", "emails"),
                           ("domain", "domains"), ("phone", "phones"),
                           ("url", "urls"), ("ip", "ips")):
        values = getattr(args, attribute, None)
        if values:
            data[key] = list(values)
    return data or None


def cmd_investigate(service: InvestigationService, args) -> int:
    result = service.investigate(
        args.raw_input,
        max_iterations=args.max_iterations,
        max_tool_calls=args.max_tool_calls,
        wall_clock_timeout_sec=args.timeout_sec,
        min_pivot_threshold=args.min_pivot_threshold,
        max_concurrent_tools=args.max_concurrent,
        target_id=args.target_id,
        scope=_parse_scope(args),
        reflection=not args.no_reflection,
        include_report=bool(args.report),
        report_format=args.report or "md",
        out_path=args.out,
        structured_seeds=_parse_structured_seeds(args),
    )
    if args.json:
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    stats = result.get("stats", {})
    print(f"Investigation {result['target_id']} -> {result['status']} "
          f"({result['stop_reason']})")
    print(f"  iterations: {result.get('iterations')}   tool calls: {result.get('tool_calls')}")
    print(f"  entities: {stats.get('entities')}   claims: {stats.get('claims')}   "
          f"artifacts: {stats.get('artifacts')}   "
          f"contradictions: {stats.get('contradictions')}")
    print(f"  state: {result.get('state_path')}")
    objectives = result.get("objectives") or []
    if objectives:
        print("  objectives:")
        for objective in objectives:
            mark = "x" if objective.get("achieved") else " "
            print(f"    [{mark}] {objective.get('description')} — {objective.get('status')}")
    actions = result.get("candidate_actions") or result.get("next_pivots") or []
    if actions:
        print("  next candidate pivots:")
        if actions and "action_id" in actions[0]:
            _print_actions(actions)
        else:
            _print_actions([
                {"action_id": pivot.get("pivot_id", "?"), "tool": pivot.get("tool_id"),
                 "score": pivot.get("score"), "rationale": pivot.get("rationale", "")}
                for pivot in actions
            ])
    if args.report and result.get("report"):
        print()
        print(result["report"]["content"])
        if result["report"].get("path"):
            print(f"\nReport written to {result['report']['path']}")
    return 0


def cmd_step(service: InvestigationService, args) -> int:
    result = service.step(args.target_id, pivot_id=args.action)
    if args.json:
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    execution = result.get("execution") or {}
    print(f"Step {result.get('iteration')} on {result['target_id']}: "
          f"{result.get('stop_reason')}")
    if result.get("action"):
        action = result["action"]
        print(f"  pivot: {action.get('pivot_id')}  tool: {action.get('tool_id')}  "
              f"entity: {action.get('entity_id')}")
        print(f"  params: {json.dumps(action.get('params', {}), ensure_ascii=False)}")
    print(f"  result: {execution.get('status')}  "
          f"error_code: {execution.get('error_code')}  "
          f"new entities: {len(result.get('record', {}).get('new_entity_ids', []))}  "
          f"new claims: {result.get('record', {}).get('new_claims')}")
    if result.get("error"):
        print(f"  note: {result['error']}")
    actions = [
        {"action_id": pivot.get("pivot_id"), "tool": pivot.get("tool_id"),
         "score": pivot.get("score"), "rationale": pivot.get("rationale", "")}
        for pivot in result.get("next_pivots", [])
    ]
    if actions:
        print("  next candidate pivots:")
        _print_actions(actions)
    else:
        print("  no next pivots (investigation halted)")
    return 0


def cmd_graph(service: InvestigationService, args) -> int:
    result = service.graph(args.target_id, view=args.view)
    if args.json or args.view not in ("summary",):
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    investigation = result["investigation"]
    graph = result["graph_summary"]
    print(f"Investigation {result['target_id']} [{investigation['status']}]")
    print(f"  stop_reason: {investigation.get('stop_reason')}")
    print(f"  nodes: {graph.get('total_nodes')}   edges: {graph.get('total_edges')}")
    print(f"  entity types: {json.dumps(graph.get('entity_types', {}), sort_keys=True)}")
    print(f"  claim statuses: {json.dumps(graph.get('claim_statuses', {}), sort_keys=True)}")
    print(f"  contradictions: {graph.get('contradictions')}")
    print("Use --view entities|claims|contradictions|hypotheses|ledger|provenance|json "
          "for detail.")
    return 0


def cmd_report(service: InvestigationService, args) -> int:
    result = service.report(args.target_id, fmt=args.format, out=args.out)
    if _is_error(result):
        if args.json:
            _print_json(result)
        else:
            print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])),
                  file=sys.stderr)
        return 1
    if args.json:
        _print_json(result)
    else:
        print(result["content"])
        if result.get("path"):
            print(f"\nReport written to {result['path']}", file=sys.stderr)
    return 0


def cmd_status(service: InvestigationService, args) -> int:
    result = service.status(args.target_id)
    if args.json:
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    investigation = result["investigation"]
    stats = result["stats"]
    print(f"Investigation {result['target_id']} [{investigation['status']}]")
    print(f"  raw input: {investigation.get('raw_input', '')[:100]}")
    print(f"  iterations: {investigation.get('iteration_count')}   "
          f"tool calls: {investigation.get('tool_calls')}   "
          f"stop_reason: {investigation.get('stop_reason')}")
    print(f"  entities: {stats.get('entities')}   claims: {stats.get('claims')}   "
          f"contradictions: {stats.get('contradictions')}")
    _print_actions(result.get("candidate_actions", []))
    return 0


def _is_port_available(host: str, port: int) -> bool:
    family = socket.AF_INET6 if ":" in host and host != "0.0.0.0" else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def _pick_free_port(host: str, preferred_port: int) -> int:
    for candidate in range(preferred_port + 1, preferred_port + 21):
        if _is_port_available(host, candidate):
            return candidate
    family = socket.AF_INET6 if ":" in host and host != "0.0.0.0" else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def _open_browser_soon(url: str) -> None:
    def _launch() -> None:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass

    timer = threading.Timer(0.6, _launch)
    timer.daemon = True
    timer.start()


def cmd_serve(service: InvestigationService, args) -> int:
    """Launch the FastAPI AI OSINT Hub Web Workbench."""
    try:
        from hub.web import run as run_web
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: web workbench unavailable: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1
    chosen_port = int(args.port)
    if getattr(args, "command", None) == "web":
        if not _is_port_available(args.host, chosen_port):
            if getattr(args, "no_port_fallback", False):
                print(
                    f"ERROR: port {chosen_port} on {args.host} is already in use",
                    file=sys.stderr,
                )
                return 1
            chosen_port = _pick_free_port(args.host, chosen_port)
            print(f"Port {args.port} is busy; using free port {chosen_port}.")
    url_host = "127.0.0.1" if args.host in {"0.0.0.0", "::"} else args.host
    url = f"http://{url_host}:{chosen_port}"
    print(f"AI OSINT Hub Intelligence Workbench → {url}")
    if getattr(args, "open", False):
        _open_browser_soon(url)
    run_web(host=args.host, port=chosen_port)
    return 0


def cmd_demo(service: InvestigationService, args) -> int:
    result = service.seed_demo(overwrite=not args.no_overwrite)
    if args.json:
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    print(
        f"✅ Seeded synthetic demo case {result.get('target_id')} "
        f"({result.get('title', 'Aurora Meridian')})"
    )
    print(
        f"   entities: {result.get('entity_count')}   "
        f"claims: {result.get('claim_count')}   "
        f"contradictions: {result.get('contradiction_count')}"
    )
    return 0


def cmd_export(service: InvestigationService, args) -> int:
    out_path = Path(args.out) if args.out else Path(f"{args.target_id}{BUNDLE_EXTENSION}")
    try:
        zip_bytes, manifest = service.export_bundle(
            args.target_id,
            out_path=out_path,
            redact_pii=bool(args.redact_pii),
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        err = {"status": "error", "errors": [str(exc)]}
        if args.json:
            _print_json(err)
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    payload = {
        "status": "ok",
        "target_id": args.target_id,
        "path": str(out_path.resolve()),
        "bytes": len(zip_bytes),
        "redacted": bool(manifest.get("redacted", False)),
        "manifest": manifest,
    }
    if args.json:
        _print_json(payload)
    else:
        print(
            f"✅ Exported {args.target_id} -> {payload['path']} "
            f"({payload['bytes']} bytes, redacted={payload['redacted']}, "
            f"files={len(manifest.get('files', {}))})"
        )
    return 0


def cmd_import(service: InvestigationService, args) -> int:
    try:
        result = service.import_bundle(
            args.bundle_path,
            overwrite=bool(args.overwrite),
            new_target_id=args.target_id,
        )
    except (FileNotFoundError, FileExistsError, ValueError, OSError) as exc:
        err = {"status": "error", "errors": [str(exc)]}
        if args.json:
            _print_json(err)
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if args.json:
        _print_json(result)
    else:
        print(
            f"✅ Imported {result['target_id']} into {result['path']} "
            f"(files={result.get('file_count')}, redacted={result.get('redacted')})"
        )
    return 0


def cmd_mcp_config(service: InvestigationService, args) -> int:
    result = service.mcp_config(client=args.client)
    if args.json:
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    print(f"MCP client: {result['client']}")
    print(f"Config path: {result['config_path_hint']}")
    print()
    print(result["snippet_json"])
    return 0


def cmd_list(service: InvestigationService, args) -> int:
    result = service.list_investigations()
    if args.json:
        _print_json(result)
        return 0
    print(f"{result['count']} investigation(s) in "
          f"{InvestigationService().engine().state_root()}:")
    for item in result["investigations"]:
        print(f"  {item['target_id']:32} {item['status']:10} "
              f"iter={item['iterations']:<3} tools={item['tool_calls']:<3} "
              f"{item.get('stop_reason') or ''}")
    return 0


def cmd_analytics(service: InvestigationService, args) -> int:
    result = service.analytics(
        args.target_id, source_id=args.source, dest_id=args.dest
    )
    if args.json:
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    summary = result.get("summary", {})
    print(f"Analytics for {result['target_id']}: "
          f"nodes={summary.get('nodes')} edges={summary.get('edges')} "
          f"components={summary.get('components')} communities={summary.get('communities')} "
          f"bridges={summary.get('bridge_entities')} hash_clusters={summary.get('perceptual_hash_clusters')}")
    for item in result.get("top_central_entities", [])[:8]:
        print(f"  {item['entity_id']:22} {item['type']:12} {item['value']:30} "
              f"deg={item['degree']} betw={item['betweenness_centrality']:.4f}")
    sp = result.get("shortest_path")
    if sp:
        if sp.get("found"):
            print(f"  shortest_path ({sp['length']} hops): {' -> '.join(sp['path'])}")
        else:
            print(f"  shortest_path: no path between {sp.get('source_id')} and {sp.get('dest_id')}")
    return 0


def cmd_timeline(service: InvestigationService, args) -> int:
    result = service.timeline(args.target_id)
    if args.json:
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    print(f"Timeline for {result['target_id']} ({result['count']} events):")
    for ev in result.get("events", [])[:40]:
        print(f"  [{ev['timestamp_utc']}] {ev['event_type']:18} {ev['title']} — {str(ev.get('detail', ''))[:80]}")
    return 0


def cmd_diff(service: InvestigationService, args) -> int:
    result = service.diff(args.target_id_a, args.target_id_b)
    if args.json:
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    summary = result.get("summary", {})
    print(f"Diff {result['target_id_a']} -> {result['target_id_b']}: "
          f"+{summary.get('added_count', 0)} added, "
          f"-{summary.get('removed_count', 0)} removed, "
          f"{summary.get('status_change_count', 0)} status changes, "
          f"{summary.get('new_contradictions_count', 0)} new contradictions")
    return 0


def cmd_ai(service: InvestigationService, args) -> int:
    if args.ai_action == "status":
        result = service.ai_status(probe_local=args.probe)
        if args.json:
            _print_json(result)
            return 0
        print(
            f"AI status: enabled={result.get('enabled')} preset={result.get('preset')} "
            f"provider={result.get('provider')} num_ctx={result.get('num_ctx')} "
            f"keep_alive={result.get('keep_alive')}"
        )
        installed = result.get("installed_models") or []
        missing = result.get("missing_models") or []
        pulls = result.get("pull_commands") or []
        if installed:
            print("  installed models: " + ", ".join(installed))
        if missing:
            print("  missing models:   " + ", ".join(missing))
        if pulls:
            print("  pull commands:    " + " && ".join(pulls))
        return 0
    result = service.ai_reflect(args.target_id, provider=args.provider)
    if args.json:
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    print(f"AI reflection ({result.get('status', 'ok')}): {result.get('summary', '')}")
    return 0


def cmd_overview(service: InvestigationService, args) -> int:
    result = service.overview(args.target_id)
    if args.json:
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    subj = result.get("subject") or {}
    counts = result.get("counts") or {}
    print(f"Overview {result['target_id']} — {subj.get('name') or result.get('raw_input', '')}")
    print(
        f"  accounts={counts.get('accounts', 0)} emails={counts.get('emails', 0)} "
        f"phones={counts.get('phones', 0)} domains={counts.get('domains', 0)} "
        f"repos={counts.get('repos', 0)} visuals={counts.get('visuals', 0)} "
        f"alerts={counts.get('alerts', 0)}"
    )
    for acc in result.get("accounts", [])[:12]:
        print(f"  [{acc['status']}] {acc['platform']}: {acc['url'] or acc['handle']} ({acc['confidence']:.2f})")
    return 0


def cmd_visuals(service: InvestigationService, args) -> int:
    if getattr(args, "upload", None):
        upload_path = Path(args.upload).expanduser()
        if not upload_path.is_file():
            err = {"status": "error", "errors": [f"file not found: {upload_path}"]}
            if args.json:
                _print_json(err)
            else:
                print(f"ERROR: file not found: {upload_path}", file=sys.stderr)
            return 1
        result = service.upload_visual(
            args.target_id,
            upload_path.name,
            upload_path.read_bytes(),
            source_label=getattr(args, "label", None) or "uploaded",
        )
    else:
        result = service.visuals(args.target_id)
    if args.json:
        _print_json(result)
        return 1 if _is_error(result) else 0
    if _is_error(result):
        print("ERROR: " + "; ".join(result.get("errors", ["unknown error"])), file=sys.stderr)
        return 1
    items = result.get("items") or ([result["item"]] if result.get("item") else [])
    print(f"Visuals for {result['target_id']} ({len(items)} item(s)):")
    for item in items:
        print(
            f"  {item.get('filename') or item.get('id')} [{item.get('source_label')}] "
            f"{item.get('width')}x{item.get('height')} phash={item.get('phash') or '-'}"
        )
    return 0


# ════════════════════════════════════════════════════════════════════════
# Parser
# ════════════════════════════════════════════════════════════════════════

def _parse_scope(args) -> Optional[dict[str, Any]]:
    scope: dict[str, Any] = {}
    if getattr(args, "allow_domain", None):
        scope["allow_domains"] = list(args.allow_domain)
    if getattr(args, "deny_domain", None):
        scope["deny_domains"] = list(args.deny_domain)
    if getattr(args, "allow_active_recon", None) is not None:
        scope["allow_active_recon"] = args.allow_active_recon
    if getattr(args, "allow_authorized_tools", False):
        scope["allow_authorized_tools"] = True
    return scope or None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-osint-hub",
        description="Autonomous, evidence-cited OSINT investigation (ERKG + pivot engine).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {CLI_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    tools = subparsers.add_parser("tools", help="live capability health check")
    tools.add_argument("--refresh", action="store_true", help="force a live re-check")
    tools.add_argument("--json", action="store_true")
    tools.set_defaults(handler=cmd_tools)

    doctor = subparsers.add_parser(
        "doctor",
        help="verify every tool with a real --version/--help smoke check")
    doctor.add_argument("--provision", action="store_true",
                        help="install missing tools into the managed bin dirs first")
    doctor.add_argument("--no-smoke", action="store_true",
                        help="inventory binaries without running --version/--help smoke checks")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(handler=cmd_doctor)

    auth = subparsers.add_parser(
        "auth", help="API credential vault (masked status / set keys)")
    auth_sub = auth.add_subparsers(dest="auth_action", required=True)
    auth_status = auth_sub.add_parser("status", help="show provider auth status")
    auth_status.add_argument("--json", action="store_true")
    auth_status.set_defaults(handler=cmd_auth)
    auth_set = auth_sub.add_parser("set", help="save a provider credential")
    auth_set.add_argument("provider",
                          choices=["github", "virustotal", "shodan", "censys", "hunter"])
    auth_set.add_argument("value", help="API key / token / Censys API ID")
    auth_set.add_argument("--censys-secret", default=None,
                          help="Censys API Secret (when provider=censys)")
    auth_set.add_argument("--censys-token", default=None,
                          help="Censys Bearer PAT (alternative to id/secret)")
    auth_set.add_argument("--json", action="store_true")
    auth_set.set_defaults(handler=cmd_auth)

    investigate = subparsers.add_parser(
        "investigate", help="run the autonomous investigation loop")
    investigate.add_argument(
        "raw_input",
        nargs="?",
        default="",
        help="seed intelligence (name, email, username, domain, text; optional when structured flags are given)",
    )
    investigate.add_argument("--target-id", default=None)
    investigate.add_argument("--max-iterations", type=int, default=None)
    investigate.add_argument("--max-tool-calls", type=int, default=None)
    investigate.add_argument("--timeout-sec", type=int, default=None)
    investigate.add_argument("--min-pivot-threshold", type=float, default=None)
    investigate.add_argument("--max-concurrent", type=int, default=None)
    investigate.add_argument("--name", default=None,
                             help="structured subject full name (Phase 8 intake)")
    investigate.add_argument("--username", action="append", default=None,
                             help="structured username clue (repeatable)")
    investigate.add_argument("--email", action="append", default=None,
                             help="structured email clue (repeatable)")
    investigate.add_argument("--domain", action="append", default=None,
                             help="structured domain clue (repeatable)")
    investigate.add_argument("--phone", action="append", default=None,
                             help="structured phone clue (repeatable)")
    investigate.add_argument("--url", action="append", default=None,
                             help="structured URL clue (repeatable)")
    investigate.add_argument("--ip", action="append", default=None,
                             help="structured IP clue (repeatable)")
    investigate.add_argument("--org", default=None,
                             help="structured organization clue")
    investigate.add_argument("--location", default=None,
                             help="structured location clue")
    investigate.add_argument("--allow-domain", action="append", default=None,
                             help="scope allowlist domain (repeatable)")
    investigate.add_argument("--deny-domain", action="append", default=None)
    investigate.add_argument("--allow-active-recon", action="store_true", default=None)
    investigate.add_argument("--allow-authorized-tools", action="store_true", default=False)
    investigate.add_argument("--no-reflection", action="store_true",
                             help="skip the quarantine-safe LLM reflection packet")
    investigate.add_argument("--report", choices=["md", "json", "html"], default=None,
                             help="also generate the evidence-cited dossier")
    investigate.add_argument("--out", default=None, help="write report to this path")
    investigate.add_argument("--json", action="store_true")
    investigate.set_defaults(handler=cmd_investigate)

    step = subparsers.add_parser("step", help="execute one pivot cycle")
    step.add_argument("target_id")
    step.add_argument("--action", default=None,
                      help="pivot_id to execute (must come from status/investigate output)")
    step.add_argument("--json", action="store_true")
    step.set_defaults(handler=cmd_step)

    graph = subparsers.add_parser("graph", help="query ERKG state")
    graph.add_argument("target_id")
    graph.add_argument("--view", default="summary",
                       choices=["summary", "entities", "claims", "contradictions",
                                "hypotheses", "ledger", "provenance", "json"])
    graph.add_argument("--json", action="store_true")
    graph.set_defaults(handler=cmd_graph)

    report = subparsers.add_parser("report", help="evidence-cited dossier")
    report.add_argument("target_id")
    report.add_argument("--format", choices=["md", "json", "html"], default="md")
    report.add_argument("--out", default=None)
    report.add_argument("--json", action="store_true")
    report.set_defaults(handler=cmd_report)

    serve = subparsers.add_parser(
        "serve", help="run the FastAPI Web Workbench (UI + REST + SSE)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(handler=cmd_serve)

    web_cmd = subparsers.add_parser(
        "web", help="launch the Web Workbench (auto-picks free port; optional browser open)")
    web_cmd.add_argument("--host", default="127.0.0.1")
    web_cmd.add_argument("--port", type=int, default=8000)
    web_cmd.add_argument("--open", action="store_true",
                         help="open the workbench URL in the default browser")
    web_cmd.add_argument("--no-port-fallback", action="store_true",
                         help="fail instead of selecting a free port if --port is busy")
    web_cmd.set_defaults(handler=cmd_serve)

    demo_cmd = subparsers.add_parser(
        "demo", help="seed the offline synthetic Aurora Meridian demo investigation")
    demo_cmd.add_argument("--no-overwrite", action="store_true",
                          help="refuse to overwrite an existing demo case")
    demo_cmd.add_argument("--json", action="store_true")
    demo_cmd.set_defaults(handler=cmd_demo)

    export_cmd = subparsers.add_parser(
        "export", help="export a case into a verified .osintcase.zip bundle")
    export_cmd.add_argument("target_id")
    export_cmd.add_argument("--out", default=None, help="output .osintcase.zip path")
    export_cmd.add_argument("--redact-pii", action="store_true",
                            help="scrub emails, phones, and secret tokens in the exported bundle")
    export_cmd.add_argument("--json", action="store_true")
    export_cmd.set_defaults(handler=cmd_export)

    import_cmd = subparsers.add_parser(
        "import", help="verify and import a .osintcase.zip case bundle")
    import_cmd.add_argument("bundle_path")
    import_cmd.add_argument("--overwrite", action="store_true",
                            help="replace an existing case with the same target_id")
    import_cmd.add_argument("--target-id", default=None,
                            help="override target_id on import")
    import_cmd.add_argument("--json", action="store_true")
    import_cmd.set_defaults(handler=cmd_import)

    mcp_cfg_cmd = subparsers.add_parser(
        "mcp-config", help="print ready-to-paste MCP server config for an AI client")
    mcp_cfg_cmd.add_argument(
        "--client",
        choices=["antigravity", "claude", "cursor", "vscode"],
        default="antigravity",
    )
    mcp_cfg_cmd.add_argument("--json", action="store_true")
    mcp_cfg_cmd.set_defaults(handler=cmd_mcp_config)

    status = subparsers.add_parser("status", help="current state + ranked pivots")
    status.add_argument("target_id")
    status.add_argument("--json", action="store_true")
    status.set_defaults(handler=cmd_status)

    listing = subparsers.add_parser("list", help="list stored investigations")
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(handler=cmd_list)

    analytics = subparsers.add_parser("analytics", help="graph centrality, clusters, bridges & path")
    analytics.add_argument("target_id")
    analytics.add_argument("--source", default=None, help="source entity_id for shortest path")
    analytics.add_argument("--dest", default=None, help="destination entity_id for shortest path")
    analytics.add_argument("--json", action="store_true")
    analytics.set_defaults(handler=cmd_analytics)

    timeline = subparsers.add_parser("timeline", help="chronological investigation event timeline")
    timeline.add_argument("target_id")
    timeline.add_argument("--json", action="store_true")
    timeline.set_defaults(handler=cmd_timeline)

    diff = subparsers.add_parser("diff", help="compare two investigations")
    diff.add_argument("target_id_a")
    diff.add_argument("target_id_b")
    diff.add_argument("--json", action="store_true")
    diff.set_defaults(handler=cmd_diff)

    ai_cmd = subparsers.add_parser("ai", help="AI status and quarantined case reflection")
    ai_sub = ai_cmd.add_subparsers(dest="ai_action", required=True)
    ai_status = ai_sub.add_parser("status", help="show masked AI configuration & health")
    ai_status.add_argument("--probe", action="store_true", help="probe local Ollama/LM Studio")
    ai_status.add_argument("--json", action="store_true")
    ai_status.set_defaults(handler=cmd_ai)
    ai_reflect = ai_sub.add_parser("reflect", help="run quarantined reflection on a case")
    ai_reflect.add_argument("target_id")
    ai_reflect.add_argument("--provider", default=None)
    ai_reflect.add_argument("--json", action="store_true")
    ai_reflect.set_defaults(handler=cmd_ai)

    overview_cmd = subparsers.add_parser("overview", help="human-friendly case overview")
    overview_cmd.add_argument("target_id")
    overview_cmd.add_argument("--json", action="store_true")
    overview_cmd.set_defaults(handler=cmd_overview)

    visuals_cmd = subparsers.add_parser("visuals", help="list or upload case visual/photo forensics")
    visuals_cmd.add_argument("target_id")
    visuals_cmd.add_argument("--upload", default=None, help="path to an image file to inspect and attach")
    visuals_cmd.add_argument("--label", default="uploaded", help="source label for uploaded image")
    visuals_cmd.add_argument("--json", action="store_true")
    visuals_cmd.set_defaults(handler=cmd_visuals)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    service = InvestigationService()
    try:
        return int(args.handler(service, args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary returns clean errors
        if getattr(args, "json", False):
            print(json.dumps({"status": "error",
                              "errors": [f"{type(exc).__name__}: {exc}"]}))
        else:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
