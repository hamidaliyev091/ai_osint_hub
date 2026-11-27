## Summary

<!-- Describe what this PR changes and why. Reference any related issue. -->

## Verification

- [ ] `python -m pytest -q --tb=short` passes offline with 0 failures
- [ ] `python -m hub.cli doctor --no-smoke` reports expected 32-tool inventory
- [ ] Tested on isolated `AI_OSINT_HUB_HOME` (no private `~/.ai_osint_hub` case data committed)

## Security & Architecture Invariants

- [ ] Closed 6-state `EpistemicStatus` preserved (`hub/models.py`)
- [ ] Every non-hypothesis claim backed by >= 1 immutable `EvidenceArtifact`
- [ ] Subprocesses use `shell=False`, `stdin=subprocess.DEVNULL` (`hub/tools/runtime.py`, `locator.py`)
- [ ] Network & image fetchers enforce `fetch_safe` / `assert_safe_host` SSRF guards
- [ ] Zero `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, or `backdrop-filter`
- [ ] AI features remain strictly opt-in (`mode="off"` / `enabled=False` default) with `PROVENANCE_AI_INFERRED` & `<untrusted_*_data>` quarantine
- [ ] Zero secrets, tokens, or API keys in code, tests, or fixtures
