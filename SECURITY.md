# Security Policy & Threat Model

AI OSINT Hub is an autonomous intelligence collection and correlation engine designed around strict defensive boundaries. External OSINT payloads, web pages, images, and imported case bundles are treated as **untrusted, potentially adversarial input**.

## Supported Versions

| Version | Supported | Notes |
|---|---|---|
| `2.0.x` | Yes | Current release (ERKG SQLite/WAL, 32-tool runtime, Gruvbox Workbench, `.osintcase.zip` bundles, optional AI layer) |
| `< 2.0.0` | No | Legacy v1 JSON-file orchestrator (deprecated; `hub.orchestrate` compatibility shim only) |

---

## Core Security Guarantees

### 1. Zero-Shell Subprocess Execution & Isolation (`hub/tools/runtime.py`, `hub/tools/locator.py`)

- Every external binary executes via `asyncio.create_subprocess_exec(*argv)` (`shell=False`) with `stdin=subprocess.DEVNULL`. Shell interpolation (`sh -c`, `cmd /c`, `bash -lc`) and batch/PowerShell `.cmd`/`.bat`/`.ps1` wrappers are rejected.
- Child processes receive a minimal allowlisted environment and an isolated temporary scratch directory. Per-tool config/state is redirected to `<repo>/.toolhome/<tool>` via trusted manifest placeholders.
- Timeouts enforce hard process-tree termination (`os.killpg` on POSIX, `taskkill /F /T` on Windows).
- Concurrency is bounded by global and heavy-local semaphores plus per-tool token buckets.

### 2. Code-Enforced Scope & Mode Policy (`hub/security/policy.py`)

Scope and execution-mode rules are enforced deterministically in Python before any subprocess spawn or HTTP socket connection — an LLM never decides whether scope is respected:

1. **`INTRUSIVE_BLOCKED` capabilities** (e.g., `hydra`) never spawn unless explicitly enabled.
2. **Authorization-gated tools** (e.g., `hashcat`) are blocked unless explicitly authorized.
3. **Passive-first default:** `ACTIVE_RECON` tools (`nmap`, `amass`, `gobuster`, `whatweb`, `hashcat`) are excluded from pivot selection unless `allow_active_recon=True` / `--allow-active-recon` is explicitly set.
4. **Hard allow/deny boundaries:** When `allow_domains` is configured, out-of-scope seeds are rejected before collection starts, and active targets must match the allowlist (or be public IPs resolved from an allowlisted domain). Deny lists always win.
5. **SSRF Protection (`assert_safe_host`, `is_public_ip`, `fetch_safe`):** Every native collector validates resolved A/AAAA records before connecting and re-validates on every manual HTTP redirect hop. Loopback (`127.0.0.0/8`, `::1`), RFC 1918 private ranges, link-local / cloud metadata (`169.254.169.254`), multicast, reserved, and unspecified addresses are blocked. DNS resolution failures fail closed.

### 3. Indirect Prompt-Injection & Visual Quarantine (`hub/security/quarantine.py`)

- All external OSINT text is stripped of ANSI escape sequences and C0/C1 control characters, literal wrapper tags are neutralized, and text is length-capped and wrapped in `<untrusted_osint_data>…</untrusted_osint_data>` with `SECURITY_SYSTEM_PROMPT`.
- Images, OCR output, EXIF/XMP/IPTC metadata, and VLM inputs pass through `sanitize_visual_text` / `wrap_visual_untrusted` (`<untrusted_visual_data>…</untrusted_visual_data>`) with `VISUAL_SECURITY_SYSTEM_PROMPT`.
- Injection heuristics (`detect_injection`, `detect_visual_injection`) flag suspicious payloads for audit visibility without altering deterministic control flow.

### 4. Epistemic Integrity & AI Non-Promotion (`hub/models.py`, `hub/erkg/`)

- `EpistemicStatus` is a closed 6-value enum: `CONFIRMED`, `CORROBORATED`, `SINGLE_SOURCE_LEAD`, `HYPOTHESIS`, `CONTRADICTED`, `COLLECTION_FAILURE`.
- Every non-hypothesis claim is backed by at least one immutable `EvidenceArtifact` (with SHA-256 hash of raw output) persisted inside atomic SQLite WAL transactions.
- **Zero-LLM default:** `AIConfig.enabled` defaults to `False` (`preset = disabled`).
- **AI non-promotion:** Any insight or VLM extraction carries `PROVENANCE_AI_INFERRED` / `PROVENANCE_VLM_EXTRACTED` (`direct=False`, bounded confidence) and can never promote a claim to `CONFIRMED` without independent deterministic tool corroboration.

### 5. Secret Vault & Redaction (`hub/credentials.py`, `hub/security/redaction.py`, `hub/ai/config.py`)

- Credentials are stored outside the repository under `$AI_OSINT_HUB_HOME` (`credentials.json`, `ai_config.json`, mode `0600` where supported) and never committed to source control.
- Registered secrets are scrubbed (`[REDACTED:<PROVIDER>]`) from tool stdout/stderr, error messages, evidence artifacts, SQLite records, CLI/MCP responses, and Web UI payloads. Only masked previews are returned over APIs.
- AI configuration never harvests credentials from `~/.dsh/.credentials.yaml`, `~/.claude/`, or `~/.codex/`.

### 6. Web Workbench & MCP App XSS / CSP Safety (`hub/web.py`, `hub/reporting.py`, `hub/mcp_server.py`)

- Embedded UIs and standalone HTML dossiers build DOM nodes strictly via `document.createElement` and `textContent` — zero `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, or `eval`.
- Rendered Markdown links enforce an explicit `http:`, `https:`, and `mailto:` scheme allowlist; `javascript:`, `data:`, and `vbscript:` URIs are stripped.
- All external vendor assets (`cytoscape.min.js`) are bundled locally with zero runtime CDN calls, and standalone HTML dossiers emit strict Content-Security-Policy (`CSP`) headers.

### 7. Portable Case Bundle Hardening (`hub/bundle.py`)

- `.osintcase.zip` imports validate every archive member against Zip-Slip traversal (`..`, absolute paths, Windows drive letters/backslashes, null bytes), Unix symlinks, compression bombs (streaming uncompressed byte cap and compression-ratio cap), and per-file SHA-256 manifest verification.
- Imported SQLite databases are verified with `PRAGMA trusted_schema = OFF` and `PRAGMA integrity_check` before atomic placement, and optional `redact_pii=True` exports scrub emails, phones, and registered secrets.

---

## Safe & Authorized Use Rules

AI OSINT Hub is intended strictly for **authorized defensive research, threat intelligence, asset attribution, and educational use**:

- Only investigate targets, domains, and infrastructure you own or have explicit written authorization to assess.
- Keep passive-first defaults (`allow_active_recon=False`) unless active reconnaissance against an explicitly allowlisted scope is authorized.
- Never enable `INTRUSIVE_BLOCKED` capabilities without formal authorization.
- Treat all collected outputs as untrusted data and validate claims through independent evidence artifacts before acting on them.

---

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

1. Report vulnerabilities privately via **GitHub Security Advisories** (`Security` -> `Advisories` -> `Report a vulnerability` on the repository) or direct maintainer contact.
2. Include:
   - Affected component/file (e.g., `hub/bundle.py`, `hub/web.py`, `hub/tools/runtime.py`, `hub/security/policy.py`).
   - Reproduction steps or a minimal proof-of-concept (offline test case preferred).
   - Impact assessment and any suggested mitigation.
3. Maintainers will acknowledge receipt, triage severity, and coordinate a fix before public disclosure.
