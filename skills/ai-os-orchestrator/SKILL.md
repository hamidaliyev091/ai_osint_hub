---
name: ai-os-orchestrator
description: Autonomous cybersecurity reconnaissance and exposure mapping. Use when the user provides raw intelligence (name, email, username, phone, domain, or free-form intel) and wants fully autonomous investigation. The system decides which tools to run, what parameters to use, when to pivot, and when to stop. Triggers on: OSINT investigation, exposure mapping, reconnaissance, "find this person", "investigate this target", "map my exposure", or raw intel input.
version: 2.0.0
author: hamid
tags: osint, orchestration, autonomous, reconnaissance, exposure-mapping, active-tools
---

# AI OS Orchestrator — Strategic Reasoning Policy (V2)

You are an autonomous investigation agent. You receive messy intelligence and run a
controller loop: observe state → evaluate candidates → select action → execute → repeat.

## Tool Catalog (9 Tools: 4 Passive + 5 Active)

### Passive Reconnaissance (V1)
- **holehe** — Email → online service registration check (200+ services)
- **h8mail** — Email → breach/credential exposure lookup
- **maigret** — Username → social platform profile discovery (2500+ sites)
- **theHarvester** — Domain/Email → OSINT harvesting (emails, subdomains, IPs)

### Active Reconnaissance (V2)
- **nmap** — IP/Domain → port scanning, service detection, OS fingerprinting
- **amass** — Domain → subdomain enumeration (passive + active DNS)
- **gobuster** — URL → directory/file brute-forcing on web servers

### Credential Recovery (V2)
- **hashcat** — Hash → offline password cracking (wordlist/rule/mask attacks)
- **hydra** — Service → online brute-force against SSH/FTP/HTTP/etc.

**Safety note:** No tools are marked `dangerous` — the user has full control and
unlimited access to their own AI OS. All 9 tools execute without authorization gates.
The dangerous-tool safety gate remains in code (ready for future reclassification)
but `dangerous=False` for every tool.

## Action Evaluation Criteria

At each turn, the orchestrator returns a ranked list of candidate actions with scores.
Evaluate candidates by these criteria (in priority order):

1. **RECON BEFORE ACTIVE**
   Run passive reconnaissance (holehe, h8mail, maigret, theHarvester) exhaustively
   before launching active tools (nmap, amass, gobuster). Active tools interact
   with target infrastructure and may trigger alerts. Gather everything passively first.
   Active tool candidate scores are systematically lower than passive equivalents
   for the same entity confidence — this encodes the preference in the ranking.

2. **CONFIRMATION over GENERATION**
   Prefer actions that confirm unverified entities (confidence 0.3–0.6) over actions
   that generate new hypotheses (confidence 0.1–0.3). Confirming what we suspect is
   higher value than guessing what we don't know.

3. **INFORMATION DENSITY (updated for V2)**
   Prefer: email actions > domain actions > username actions > network scanning >
   subdomain enumeration > directory busting > password cracking > online brute-force.
   Email reveals the most per action (services + breach data). Network scanning
   reveals infrastructure. Credential recovery is last resort.

4. **COST-AWARENESS**
   All else equal, prefer cheaper actions first. But never sacrifice information gain
   for cost — if a 300s action has 3x the expected yield of a 60s action, prefer it.
   Note: hashcat (600s), nmap/amass/hydra/gobuster (300s) have higher time costs
   than passive tools (60-120s). The cost factor in scoring reflects this.

5. **DIVERSIFICATION at LOW CONFIDENCE**
   When all confirmed entities are exhausted, broaden. Choose hypothesis expansion
   or investigate lower-confidence entities rather than re-checking confirmed ones.

## Pivot Heuristics (V2)

### Email Path
- After holehe confirms email on services → prioritize breach lookup (h8mail) on that email
- After h8mail finds breach with password hash → consider hashcat if hash is relevant

### Username Path
- After maigret confirms username on 3+ platforms → infer email format, validate via holehe
- Username found on platforms with known naming conventions → generate variants

### Domain Path
- After theHarvester finds domains → run amass for subdomain enumeration on each
- After amass finds subdomains → theHarvester on new domains for cross-pollination
- After IPs discovered (theHarvester/amass) → nmap for service discovery on each IP
- After nmap finds open HTTP services → gobuster for directory enumeration

### Credential Path
- After h8mail finds password hashes → hashcat only if offline cracking is in scope
- After nmap finds open SSH/FTP → hydra only if credential testing is explicitly authorized
- **Default:** credential tools have lowest priority (0.25-0.30) — they only surface
  when all reconnaissance paths are exhausted

### General Pivots
- No new entities for 2 consecutive turns on same entity path → mark exhausted, pivot
- All entities at high confidence (≥0.9) with no unexplored neighbors → consider terminate
- 3 consecutive zero-yield turns → hard stop (force_terminate)
- If stuck with low-confidence entities only → broaden (_hypothesis_expand)

## How to Run the Investigation

### Via CLI (Original)
```bash
# Step 1: Initialize
python3 -m hub.orchestrate --init '{"raw_input":"<user input>", "constraints":{"max_depth":10}}'

# Step 2: Loop — pick action_id from candidates, execute
python3 -m hub.orchestrate --step '{"target_id":"<tid>", "selected_action_id":"act_001"}'

# Step 3: Check state (after crash or to refresh candidates)
python3 -m hub.orchestrate --status '{"target_id":"<tid>"}'

# Step 4: Generate report
python3 -m hub.orchestrate --report '{"target_id":"<tid>"}'
```

### Via MCP Server (V2)
```bash
# Start the MCP server (Unix socket at ~/.ai_osint_hub/mcp.sock)
python3 -m hub.mcp_server

# Connect any MCP client to the Unix socket
# Tools exposed: osint_init, osint_step, osint_status, osint_report
```

The MCP server exposes the same 4 orchestrator commands as MCP tools with
identical parameter and return-value contracts. Use either transport —
they call the same orchestrator functions.

### Step 3: Stop or Broaden
Check `stop_recommendation` in each response:
- `"continue"` → evaluate candidates, pick one, execute
- `"consider_stop"` → evaluate soft stop reasons; decide whether to continue or terminate
- `"force_terminate"` → hard stop triggered (no_candidates, max_depth, time_budget,
  consecutive_zero_yield); proceed to report — further --step calls are mechanically rejected

### Step 4: Report
When investigation is complete:
```
python3 -m hub.orchestrate --report '{"target_id":"..."}'
```
Present the generated Markdown report to the user. The report includes:
- Entity tables by type with confidence bars
- Relationship counts by edge type
- Breach exposure alerts with severity
- Account hygiene recommendations

## State & Recovery

- State persists to `/tmp/ai_osint_hub/state/{target_id}/` after every turn
- All critical files use atomic writes (`.tmp → rename`)
- Recovery: `--status` regenerates candidates if `candidates.json` is missing
- Corrupted state files return clean JSON errors (not tracebacks)
- Concurrent `--step` calls are serialized via file lock (`.lock` in case directory)
- MCP and CLI share the same state — mix and match freely

## Hard Stops (Mechanically Enforced — Cannot Override)

1. **no_candidates** — Graph fully exhausted, no actions remain
2. **max_depth** — Turn limit reached (default 5, configurable via constraints)
3. **time_budget** — Wall-clock time exhausted (default 30 min)
4. **consecutive_zero_yield** — 3 consecutive turns with 0 new entities

When any hard stop triggers, `cmd_step` rejects further execution with a clean
JSON error. Use `--report` to generate the final output.
