# AI OSINT Hub: Enterprise-Grade Autonomous OSINT & Threat Attribution Engine
**Technical Architecture & Candidate Presentation for PROSOL**
**Presenter:** Hamid Aliyev
**Target Role:** Cyber Threat Intelligence (CTI) / Security Automation / OSINT Analyst

---

> [!IMPORTANT]
> **Executive Summary for PROSOL Evaluators**
> AI OSINT Hub is a hardened, production-grade intelligence gathering and entity-resolution platform (v2.1.0). Unlike brittle OSINT scripts or hallucination-prone "AI wrappers", it operates on a **zero-LLM deterministic core** backed by SQLite Write-Ahead Logging (WAL), mathematical epistemic confidence scoring, code-enforced defensive security boundaries (SSRF protection, non-intrusive policy gating), and automated visual forensics (EXIF, GPS, 64-bit perceptual hashing).

---

## Slide 1: Title & Executive Overview

### The Vision: Recruiter-Grade OSINT Automation
* **Project:** AI OSINT Hub (v2.1.0)
* **Candidate:** Hamid Aliyev
* **Target:** PROSOL — Cyber Threat Intelligence, Incident Response & SOC Operations
* **Repository:** [github.com/hamidaliyev091/ai_osint_hub](https://github.com/hamidaliyev091/ai_osint_hub)
* **Core Philosophy:** *Zero bloat, deterministic ground truth, strict defensive boundaries, and intelligence that analysts can trust in court and client briefs.*

```
+----------------------------------------------------------------------------------+
|                            AI OSINT HUB v2.1.0                                   |
|   32 Integrated Tools | Closed 6-State Epistemics | Automated Visual Forensics   |
|   SSRF & Policy Gated | SQLite WAL Transactional  | 4 Enterprise Themes          |
+----------------------------------------------------------------------------------+
```

> **Speaker Notes:**
> *"Good morning / afternoon members of the PROSOL team. Today I am presenting AI OSINT Hub — an autonomous intelligence collection and threat attribution workbench that I engineered to solve the most painful operational bottlenecks in modern threat intelligence, investigation, and incident response."*

---

## Slide 2: The Core Problem in Modern Threat Intelligence

### Operational Bottlenecks in Today's SOC & CTI Teams:
1. **Tool Fragmentation & Chaos:**
   Analysts juggle 10–20 standalone CLI tools (`theHarvester`, `holehe`, `sherlock`, `maigret`, `shodan`, `whois`), manually scraping terminals, copying hashes, and stitching notes into spreadsheets.
2. **"AI Wrapper" Hallucination Risk:**
   Tools that blindly pipe raw internet text into generative LLMs introduce catastrophic false positives, hallucinations, and unbacked claims that cannot stand up in forensic reports or customer briefings.
3. **Noisy False Positives & Synthetic Accounts:**
   Generic paths (`/members`, `/login`) and bot committers (`web-flow`, `dependabot[bot]`) contaminate identity clusters.
4. **Defensive Hazards & Operational Security (OPSEC):**
   Uncontrolled crawling triggers Server-Side Request Forgery (SSRF), internal network scanning, or accidental intrusive probes that violate engagement scope.

---

## Slide 3: System Architecture — 5-Layer Deterministic Pipeline

AI OSINT Hub enforces a strict unidirectional pipeline where **claims cannot exist without cryptographic evidence**.

```
+-----------------------------------------------------------------------------+
| 1. MULTI-CLUE INTAKE                                                        |
|    Names, Handles, Emails, Domains, IPs, Visuals (Transliteration Aware)    |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| 2. POLICY & SCOPE GATE                                                      |
|    SSRF Guard (assert_safe_host) | Active Recon Policy | Hydra Auto-Block   |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| 3. HARDENED TOOLCHAIN RUNTIME (32 Tools)                                    |
|    Native HTTP (crt.sh, RDAP, BGP) | APIs | Managed CLIs | WSL2 Bridge      |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| 4. EVIDENCE INGESTOR & ERKG STORE                                           |
|    SHA-256 Artifacts | SQLite WAL | Closed 6-State Epistemics | Unification |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| 5. PARITY PRESENTATION INTERFACES                                           |
|    FastAPI Web Workbench (4 Themes) | FastMCP Stdio | Headless CLI | Dossier|
+-----------------------------------------------------------------------------+
```

---

## Slide 4: Epistemic Truth Model & Entity Resolution

### The Closed 6-State Epistemic Enum (`hub.models.EpistemicStatus`)
Every claim in the Entity-Relationship Knowledge Graph (ERKG) is strictly classified into one of six states:

| Epistemic Status | Operational Definition | Mathematical Criteria |
| :--- | :--- | :--- |
| `CONFIRMED` | Indisputable ground truth | Verified primary seed or multi-source cryptographically corroborated evidence. |
| `CORROBORATED` | High confidence | $\ge 2$ independent tool collectors confirming the exact same predicate and object. |
| `SINGLE_SOURCE_LEAD` | Uncorroborated lead | 1 external tool output; flagged for analyst verification before citing. |
| `HYPOTHESIS` | Planner candidate | Generated via structured transliteration / permutations; strictly bounded (confidence $\le 0.35$). |
| `CONTRADICTED` | Mutually exclusive conflict | A functional predicate received conflicting verified claims; alerts analyst immediately. |
| `COLLECTION_FAILURE` | Audit record | Tool crashed, timed out, or hit rate limit; recorded in execution ledger to prevent repeat failure. |

### Key Resolution Improvements in v2.1.0:
* **Multi-Valued `HAS_EMAIL`:** Legitimate targets have multiple personal and corporate emails. `HAS_EMAIL` is non-functional; multiple emails enrich the profile without triggering false contradictions.
* **Automated Person Unification (`_unify_duplicate_persons`):** When seed clues and discovered accounts share verified unique handles or non-role emails, duplicate `PERSON` entities automatically merge into a single identity card.
* **Provider Infrastructure Tagging:** Freemail domains (`gmail.com`, `mail.ru`) and synthetic addresses (`*@users.noreply.github.com`) are tagged as infrastructure, preventing fake domain ownership claims.

---

## Slide 5: Defensive Security & Sandboxing (Zero Host Risk)

Designed with enterprise security postures appropriate for PROSOL's high-security environments:

1. **Pre-Spawn SSRF & Host Validation (`assert_safe_host`):**
   * Rejects loopback (`127.0.0.0/8`, `::1`), private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and AWS/cloud link-local metadata endpoints (`169.254.169.254`).
   * Enforces manual redirect loops with re-validation on every hop to eliminate redirect SSRF bypasses.
2. **Non-Intrusive Policy Guard (`INTRUSIVE_BLOCKED`):**
   * Brute-force and intrusive attack tools (e.g. `hydra`) are strictly policy-blocked (`policy_blocked=True`). They display honestly as `BLOCKED` in UI and tool diagnostics, never spawning unmonitored attacks.
3. **Shell-Free Subprocess Execution:**
   * Every CLI tool is spawned with `shell=False` and `stdin=DEVNULL`. Shell injection is architecturally impossible.
4. **Quarantine & Anti-Prompt-Injection:**
   * External OSINT data is sanitized and wrapped in protective boundaries (`<untrusted_osint_data>` and `<untrusted_visual_data>`) before reaching any optional AI reflection layer.

---

## Slide 6: Visual Forensics & Cross-Platform Avatar Correlation

A standout capability in v2.1.0: **Automated Visual Intelligence Gathering**.

```
+-----------------------------------------------------------------------------------+
|  Target Input: "Aurora Vance" / "aurora_vance_sec" / "aurora@aurora-defense.az"   |
+-----------------------------------------------------------------------------------+
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
 [GitHub Collector]                                 [Gravatar Collector]
  avatar_url: avatars.githubusercontent.com/...       avatar_url: gravatar.com/avatar/...
         |                                                   |
         +-------------------------+-------------------------+
                                   |
                                   v
             [Visual Harvester (SSRF-Safe, Max 5MB, MIME)]
                                   |
                                   v
               [64-Bit Perceptual Hashing (dHash + pHash)]
                                   |
             * GitHub Avatar pHash:   0x8f7e3c1a9b2d4e6f
             * Gravatar Avatar pHash: 0x8f7e3c1a9b2d4e6f
             * Hamming Distance: 0 (Exact Visual Match)
                                   |
                                   v
       [Automatic Identity Link: Same Individual Across Disparate Networks]
```

### Visual Intelligence Features:
* **Passive Avatar Discovery:** Automatically extracts profile photos from GitHub profiles, Gravatar hashes (`d=404` validation), and social OpenGraph tags (`og:image`, `twitter:image`).
* **EXIF & Geolocation Extraction:** Strips and parses camera models, software tags, and GPS coordinates if present.
* **Perceptual Hashing Matching:** Flags matching avatars across accounts even if images were resized, recompressed, or stripped of metadata by social platforms.
* **Analyst File Upload:** 1-click drag-and-drop forensics for local evidence photos.

---

## Slide 7: 32-Tool Enterprise Toolchain Matrix

AI OSINT Hub incorporates 32 specialized reconnaissance capabilities across four execution tiers:

* **1. Python-Native Passive Collectors (Zero External Binary Dependencies):**
  `dns_lookup`, `virustotal_lookup`, `tls_cert`, `rdap_lookup`, `crtsh_lookup`, `asn_bgp_lookup`, `favicon_hash`, `media_forensics`, `photon_crawler`, `wayback_machine`, `gravatar_probe`, `openpgp_search`, `ahmia_search`.
* **2. Authenticated Intelligence APIs (Safe Key Vault + Auto Redaction):**
  `shodan_lookup`, `censys_lookup`, `github_osint`.
* **3. Managed OSINT CLIs (Isolated Sandboxed Virtual Environments):**
  `theharvester`, `holehe`, `sherlock`, `maigret`, `phoneinfoga`, `ghunt`, `h8mail`.
* **4. System & Network Reconnaissance (Direct Windows or Seamless WSL2 Bridge):**
  `whois`, `dig`, `nmap` (passive), `traceroute`, `snscrape`.

---

## Slide 8: Enterprise Workbench UI & Cross-Screen Design

Engineered for SOC analyst ergonomics across **13" field laptops, 1080p desktop stations, and ultrawide command centers**:

* **Clean Layout:** Cases rail on the left with 1-click case creation and instant tool diagnostics.
* **Overview Tab First:** Verified Accounts card, discovered email addresses, domains, and repositories displayed immediately.
* **Visuals & Photos Gallery:** Responsive photo grid showing source platform, image dimensions, EXIF status, and perceptual similarity matches.
* **Interactive Correlation Graph:** Cytoscape `cose` force-directed graph with solid matte label pills and auto-selected subject inspector.
* **4 Instant Themes:**
  1. **Clean Light (Default):** Crisp linear white/slate for high visibility.
  2. **Warm Paper:** Soft parchment tones for reduced eye strain.
  3. **Midnight Slate:** Low-light dark mode for 24/7 SOC environments.
  4. **Gruvbox Dark:** High-contrast terminal styling.

---

## Slide 9: Pragmatic, Local-First AI Integration

* **Zero-LLM Core by Default:** Complete intelligence collection, entity resolution, and confidence math run deterministically without cloud or GPU costs.
* **Optional Built-in `[local-ai]` (ONNX Runtime):**
  * Powered by `fastembed` — zero daemons, zero external processes, zero GPU required.
  * Provides offline semantic alias matching and CLIP cross-modal visual search.
* **BYOK Support for Cloud & Local LLMs:**
  * Clean support for Ollama, LM Studio, Google Gemini, DeepSeek, and OpenAI-compatible endpoints.
* **Analyst Safety Guarantee:**
  * Any AI output is tagged `AI_INFERRED` with confidence capped at $\le 0.35$ (text) or $\le 0.45$ (visuals). AI never overrides verified evidence.

---

## Slide 10: Live Demonstration Walkthrough Script (5 Minutes)

```powershell
# 1. Verify system toolchain integrity (Expected: 32/32 AVAILABLE)
python -m hub.cli doctor

# 2. Seed synthetic demonstration case (Aurora Vance - Threat Actor / Executive Profile)
python -m hub.cli demo

# 3. Launch Web Workbench with automated browser opening
python -m hub.cli web --open
```

### Demonstration Flow:
1. **Tool Integrity:** Show `python -m hub.cli doctor` returning 32/32 available with Hydra clearly flagged as `BLOCKED`.
2. **Overview Tab:** Highlight the unified identity of *Aurora Vance*, showing cross-platform accounts linked without duplicate fragmentation.
3. **Visuals Tab:** Show the perceptual hash match between GitHub and Gravatar avatars.
4. **Theme Switcher:** Switch between Clean Light and Midnight Slate to show cross-screen adaptability.
5. **Graph & Dossier Export:** Show the Cytoscape correlation graph and 1-click `.osintcase.zip` export.

---

## Slide 11: Direct Value Proposition for PROSOL

| PROSOL Business Unit | Operational Challenge | How AI OSINT Hub Solves It |
| :--- | :--- | :--- |
| **Cyber Threat Intelligence (CTI)** | Manual actor profiling takes hours of tedious searching. | Automated pivot engine correlates handles, emails, and keys in under 90 seconds. |
| **Incident Response & DFIR** | Rapid external surface analysis of compromised identities. | Maps exposed repositories, public PGP keys, and social breadcrumbs instantly. |
| **Red Team & Penetration Testing** | Passive recon must be non-intrusive and auditable. | Enforces strict passive boundaries, SSRF blocks, and immutable execution logs. |
| **SOC & Client Reporting** | Client deliverables must be verifiable and professional. | Instant presentation-ready HTML/PDF dossiers with cryptographic artifact backing. |

---

## Slide 12: Technical Defense & Anticipated Q&A

* **Q: "Why not just use Maltego?"**  
  *A:* Maltego requires heavy manual graph manipulation and proprietary transforms. AI OSINT Hub provides fully automated async collection, deterministic entity resolution, and zero licensing lock-in.
* **Q: "How is investigator OPSEC preserved?"**  
  *A:* Passive collectors query public third-party caches (crt.sh, RDAP, Wayback) rather than touching target servers. Centralized HTTP routing allows routing all traffic through SOCKS5/corporate VPN proxies.
* **Q: "Can an attacker compromise the system via prompt injection?"**  
  *A:* All external strings pass through `hub.security.quarantine`. Crucially, core ERKG reasoning is 100% deterministic code—an LLM never makes graph mutation decisions.

---

## Slide 13: Summary & Candidate Value

* **Architecture Mastery:** Designed and verified end-to-end async Python, SQLite WAL transactions, and multi-tier tool execution.
* **Defensive Engineering:** Strict SSRF validation, policy gates, and input sanitization baked into every subsystem.
* **Production Polish:** 745 automated tests, 32/32 healthy tools, responsive multi-theme interface, and clean documentation.
* **Mission Alignment:** Ready to elevate PROSOL's CTI, DFIR, and automated reconnaissance capabilities on day one.
