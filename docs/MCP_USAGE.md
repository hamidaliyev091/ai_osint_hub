# MCP Server Usage Guide

The AI OSINT Hub exposes orchestrator commands as MCP (Model Context Protocol) tools
via a Unix domain socket, allowing any MCP-compatible client to drive investigations.

## Starting the Server

```bash
python3 -m hub.mcp_server
```

Listens on `~/.ai_osint_hub/mcp.sock` via SSE transport over HTTP.
Uses uvicorn with the FastMCP ASGI app.

## MCP Tools

| Tool | Description | Key Parameters |
|------|-------------|---------------|
| `osint_init` | Start new investigation | `raw_input`, `max_depth`, `time_budget_minutes` |
| `osint_step` | Execute one action | `target_id`, `selected_action_id`, `max_depth` |
| `osint_status` | Get current state | `target_id` |
| `osint_report` | Generate Markdown report | `target_id` |

## Example Session

```
Client: osint_init(raw_input="investigate john.doe@example.com", max_depth=10)
Server: { "status": "initialized", "target_id": "case_20260626_120000", "candidate_actions": [...] }

Client: osint_step(target_id="case_20260626_120000", selected_action_id="act_000")
Server: { "turn": 1, "execution_status": "success", "new_entities_count": 15, ... }

Client: osint_report(target_id="case_20260626_120000")
Server: { "status": "complete", "report_md": "# Investigation Summary...", ... }
```

## Transport Details

- **Protocol:** MCP over SSE (Server-Sent Events)
- **Socket:** Unix domain socket at `~/.ai_osint_hub/mcp.sock`
- **Library:** `mcp` PyPI package 1.28+ (FastMCP), `uvicorn` ASGI server
- **Concurrency:** Same investigation file lock applies (P0-7) — concurrent steps on the same target_id are serialized

## CLI Compatibility

The MCP server calls the same `cmd_init`, `cmd_step`, `cmd_status`, `cmd_report`
functions as the CLI. State is shared — you can start an investigation via CLI
and resume it via MCP, or vice versa. Both read/write to `/tmp/ai_osint_hub/state/`.

## Error Handling

- Corrupted state files return clean JSON errors with `"status": "error"` and descriptive messages
- Tool execution failures return `"execution_status": "error"` with `parse_errors` array
- Hard stops return `"stop_recommendation": "force_terminate"` — further steps are mechanically rejected
- Lock timeout (10s) returns clean error if another process holds the investigation lock
