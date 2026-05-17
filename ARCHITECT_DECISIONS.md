# repo-guard — Architect Decisions

This file documents key design decisions made during the build of repo-guard.
It exists to distinguish deliberate choices from accidental ones, and to provide
context for contributors, reviewers, and future maintainers.

---

## Foundation

### AD-001 — Models defined before any module
**Decision**: `models.py` was written and tested before any module, reporter,
or CLI code was touched.

**Rationale**: Every module returns a `ModuleResult`. Every reporter consumes
a `ScanResult`. Defining these contracts first meant no module could return
raw dicts, strings, or ad-hoc structures. The type system enforces the
architecture.

**Tradeoff**: Slightly more upfront work. Eliminated an entire class of
integration bugs.

---

### AD-002 — Single GitHub API client
**Decision**: All GitHub API calls go through `github_client.py`. No module
calls `requests` directly.

**Rationale**: Rate limit handling, authentication, and error normalization
live in one place. If GitHub changes an endpoint or we add token rotation,
one file changes — not four modules.

**Tradeoff**: Modules are slightly less self-contained. Worth it for
maintainability.

---

### AD-003 — No cloning, ever
**Decision**: repo-guard fetches file contents via GitHub Contents API and
repo trees via Git Trees API. It never runs `git clone`.

**Rationale**: This is a pre-execution defense tool. Cloning would defeat the
entire purpose — git hooks fire on checkout events. Fetching via API means
zero execution risk regardless of what the repo contains.

**Tradeoff**: Some repo structures are harder to traverse via API than via
local filesystem. Acceptable for MVP scope.

---

## Modules

### AD-004 — Trust score is context, not a block
**Decision**: A low trust score alone does not fail a scan or produce a
CRITICAL finding. It is always accompanied by the specific signals that
triggered it.

**Rationale**: Trust score is probabilistic. A 20-day-old account with one
repo might be a legitimate new developer. Combined with a malicious hook file
it becomes damning. The score provides context for the other modules, not a
verdict by itself.

**Tradeoff**: Less dramatic output for edge cases. More accurate.

---

### AD-005 — Contributor checks capped at 10
**Decision**: `trust_score.py` checks a maximum of 10 contributors for
suspension/deletion, even if a repo lists more.

**Rationale**: Each contributor check is one GitHub API call.
Unauthenticated rate limit is 60 requests/hour. A repo with 100 contributors
would burn the entire quota on a single module. The first 10 contributors are
the most relevant signal anyway — malicious repos typically have 1–3 accounts.

**Tradeoff**: Suspended contributors beyond position 10 are not detected.
Documented limitation. Can be raised with `--token` in a future pass.

---

### AD-006 — Comment-to-code ratio heuristic in hook scanner
**Decision**: Hook files with >70% comment lines AND network commands present
are flagged as suspicious, independent of the execution pattern detection.

**Rationale**: The FlexPay attack buried 6 lines of payload under 40 lines
of decoy shell comments. This is statistically anomalous — legitimate hook
files are not 87% comments. The ratio heuristic catches obfuscation patterns
that regex alone might miss if the payload syntax is novel.

**Tradeoff**: Potential false positives on heavily commented legitimate hooks.
Mitigated by requiring both conditions (ratio AND network commands).

**Origin**: Derived directly from the live attack that motivated this tool.
This is original detection logic, not documented elsewhere at time of writing.

---

### AD-007 — Base64 detection owned by ioc_extractor
**Decision**: `hook_scanner.py` imports `_extract_base64_blobs` from
`ioc_extractor.py` rather than implementing its own base64 detection.

**Rationale**: Two separate base64 implementations diverged immediately —
hook_scanner used a 40-char threshold with no validation, ioc_extractor used
21-char threshold with printability checks and hex filtering. The safer
implementation (ioc_extractor) now owns the logic. Single source of truth.

**Tradeoff**: hook_scanner has a dependency on ioc_extractor. Acceptable
given they're sibling modules in the same package.

---

### AD-008 — Boolean flags replace message string sniffing
**Decision**: `vscode_scanner.py` tracks `has_folder_open` and
`has_allow_auto` as explicit booleans returned from sub-functions, not by
searching finding message strings.

**Rationale**: String sniffing on finding messages is brittle. Any wording
change silently breaks combined-condition detection. Boolean flags are
refactor-safe — the condition logic doesn't depend on human-readable output.

**Tradeoff**: Slightly more verbose function signatures. Correct behavior
is worth it.

---

### AD-009 — VirusTotal enrichment is optional, never blocking
**Decision**: IOC extraction runs regardless of whether a VT API key is
provided. If no key: IOCs are listed without reputation scores, output notes
how to add enrichment.

**Rationale**: The core value of the IOC extractor is extraction — surfacing
wallet addresses, domains, and decoded base64. VT reputation is additive.
Making VT required would break the tool for users who just want the IOC list.

**Tradeoff**: Users without VT keys get less enriched output. This is
clearly communicated, not silently degraded.

---

## Testing

### AD-010 — No live API calls in any test
**Decision**: Every HTTP call in every test is mocked via `responses` library
or `unittest.mock.patch`. Static fixture files are loaded from disk.

**Rationale**: Live API calls make tests non-deterministic, rate-limited,
and dependent on external infrastructure. A test suite that fails when GitHub
is slow is not a test suite.

**Enforcement**: Kimi (research agent) audits each phase for live call
violations before the phase is cleared. This caught a violation in Phase 2
that was fixed before Phase 3 began.

---

### AD-011 — FlexPay fixture is the canary test
**Decision**: `tests/fixtures/flexpay_mock/` is a static replica of the
real attack chain that motivated this tool. It must trigger CRITICAL or
WARNING in hook_scanner and vscode_scanner. If it returns CLEAN, the build
is broken.

**Rationale**: The tool exists because of this specific attack. If it can't
detect the attack that created it, nothing else matters.

**Note**: The fixture uses sanitized/neutered payload URLs. No live malware
infrastructure is contacted at any point.

---

### AD-012 — Pytest gates between every phase
**Decision**: No phase proceeds until all tests from all previous phases
pass. Any regression blocks forward progress until fixed.

**Rationale**: Incremental validation catches breakage at the boundary where
it's introduced, not three phases later when the cause is obscured.

**Implementation**: DeepSeek implements, Kimi audits independently before
phase clearance. Two-agent review process caught real issues in both Phase 2
and Phase 3.

---

## What Was Deliberately Not Built

### AD-013 — No LLM/AI inference in detection
**Decision**: All detection is deterministic. No module calls an LLM to
classify findings.

**Rationale**: LLM-based detection hallucinates. A security tool that flags
threats that don't exist destroys trust faster than missing a threat. Scoring
is math, pattern matching is regex, risk assessment is boolean logic.

**Future**: Ollama integration for plain-English narrative summary of scan
results is a documented future contribution. It would wrap the deterministic
output, never replace it.

---

### AD-014 — No typosquatting engine in MVP
**Decision**: Package name fuzzy-matching against the npm registry top 1000
was scoped out of MVP.

**Rationale**: This is a solved problem in academic literature but a
significant engineering effort to implement correctly. Snyk and Socket.dev
already do this well. repo-guard's unique value is pre-clone IDE and hook
scanning — not re-implementing what existing tools already cover.

**Future**: Levenshtein distance matching against a curated package list is
a natural Phase 2 feature.

---

### AD-015 — No contributor network graph in MVP
**Decision**: Pivoting from a suspended contributor to their other repos
(threat actor attribution) was scoped out of MVP.

**Rationale**: `ferext` (suspended contributor in the FlexPay attack) may
have left traces in other repos. Traversing that graph is real threat intel
methodology but requires significant API quota and graph traversal logic.

**Future**: High value for the security research audience. Natural extension
once the core scanner is stable.

---

### AD-016 — hook_scanner imports from ioc_extractor
Decision: hook_scanner.py imports _extract_base64_blobs from ioc_extractor rather than duplicating logic. Acknowledged coupling between sibling modules. Acceptable for MVP. If the project grows, extract to utils/base64_utils.py as a shared utility.

---

*This document is maintained by the project architect.*
*Last updated: Phase 3 complete.*