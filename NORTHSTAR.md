# repo-guard — Build Plan

## What This Is

A CLI security scanner for GitHub repositories that inspects for malicious
IDE configuration, git hooks, and suspicious metadata **before you clone**.

Built in response to a real North Korean APT (Lazarus Group / Contagious
Interview) recruitment scam that used exactly these vectors. No existing tool
covers this attack surface.

---

## Target User

Junior to mid-level Web3 developers who receive GitHub repo links from
recruiters or collaborators and need a fast, trustworthy way to know if
opening it in VS Code will execute malware.

---

## What It Is Not

- Not a replacement for Snyk, Socket.dev, or npm audit (those run post-clone)
- Not a general supply chain security platform
- Not an AI-powered tool (deterministic scoring only, no LLM)

---

## CLI Interface

```bash
# Basic scan (public repo, no auth)
repo-guard scan <github_url>

# Private repo or higher rate limits
repo-guard scan <github_url> --token <github_pat>

# With VirusTotal enrichment
repo-guard scan <github_url> --vt-key <virustotal_api_key>

# Machine-readable output
repo-guard scan <github_url> --json

# Preview suspicious file contents in terminal without downloading
repo-guard scan <github_url> --preview

# Recruiter context (optional social engineering flag)
repo-guard scan <github_url> --recruiter <linkedin_url_or_text>
```

---

## Project Structure

```
repo_guard/
├── repo_guard/
│   ├── __init__.py
│   ├── cli.py                  # Entry point, argparse, orchestration
│   ├── github_client.py        # All GitHub API calls, single source of truth
│   ├── models.py               # Dataclasses for all scan results
│   ├── reporter.py             # Terminal output formatting, JSON output
│   └── modules/
│       ├── trust_score.py      # Module 1 — Account & repo metadata
│       ├── hook_scanner.py     # Module 2 — .githooks payload detection
│       ├── vscode_scanner.py   # Module 3 — .vscode auto-execution detection
│       └── ioc_extractor.py    # Module 4 — IOC extraction & VT enrichment
├── tests/
│   ├── fixtures/
│   │   ├── flexpay_mock/       # FlexPay attack chain static files
│   │   │   ├── .githooks/
│   │   │   │   └── post-checkout  # 40 lines decoy comments + 6 payload lines
│   │   │   ├── .vscode/
│   │   │   │   ├── tasks.json  # runOn: folderOpen
│   │   │   │   └── settings.json
│   │   │   └── README.md
│   │   └── clean_repo/         # Benign repo structure, all modules return CLEAN
│   │       ├── .vscode/
│   │       │   └── settings.json
│   │       └── src/
│   │           └── main.py
│   ├── test_models.py
│   ├── test_github_client.py
│   ├── test_reporter.py
│   ├── test_cli.py
│   ├── test_trust_score.py
│   ├── test_hook_scanner.py
│   ├── test_vscode_scanner.py
│   ├── test_ioc_extractor.py
│   └── test_integration.py
├── pyproject.toml
├── README.md
├── IOC_FEED.md
├── NORTHSTAR.md
├── NORTHSTAR2.md
└── PLAN.md
```

---

## Core Architecture Decisions

### GitHub API Strategy
- Single `github_client.py` handles all requests
- Repo URL parsed into owner/repo at CLI entry point
- Files fetched via GitHub Contents API (no cloning, ever)
- Repo tree fetched via Git Trees API
- Unauthenticated by default (60 req/hr), `--token` for 5000 req/hr
- All API calls go through one client so rate limit handling is centralized

### Models First
`models.py` defines dataclasses before any module is written. Every module
returns a consistent result type. The reporter and CLI consume these types,
never raw module output.

```python
# Severity levels
CLEAN / INFO / WARNING / CRITICAL

# Every module returns a ModuleResult
ModuleResult:
    module_name: str
    severity: Severity
    findings: list[Finding]
    raw_data: dict  # for --json output

# Aggregated by cli.py into ScanResult
ScanResult:
    repo_url: str
    repo_owner: str
    repo_name: str
    scanned_at: datetime
    overall_severity: Severity  # highest of all modules
    modules: list[ModuleResult]
```

### Execution Order
1. Trust Score (account/repo metadata — sets context for everything else)
2. Hook Scanner (.githooks)
3. VS Code Scanner (.vscode/tasks.json + settings.json)
4. IOC Extractor (all text files, VT enrichment if key provided)

All four run by default. No selective module flags in MVP.

### Output
- **Terminal**: color-coded by severity, one section per module, overall
  risk summary at bottom
- **JSON**: `--json` flag, same structure, pipeable
- Colors: CRITICAL=red, WARNING=yellow, INFO=cyan, CLEAN=green

### Failure Modes (explicit, not silent)
| Condition | Behavior |
|-----------|----------|
| Private repo, no token | Clear error: "Private repo detected. Re-run with --token" |
| No .githooks directory | Module 2 returns CLEAN, notes absence |
| No .vscode/tasks.json | Module 3 returns CLEAN, notes absence |
| No VT key | IOC extractor runs, skips enrichment, notes in output |
| Rate limited | Explicit message with rate limit reset time |
| Network error | Caught, reported, scan continues where possible |

---

## Module Specifications

### Module 1 — Trust Score (`trust_score.py`)
**Purpose**: Score the repository and account before any file inspection.
A low trust score alone is not a block — it's context for the other findings.

**Data sources** (all via GitHub API, no scraping):
- Account creation date → days since creation
- Public repo count
- Follower / following counts
- Contributor list → check each for suspension/deletion
- Commit history → total commits, date range, force-push indicators
- Repo creation date vs first commit date

**Scoring (0–100, higher = more trustworthy)**:
| Signal | Weight | Notes |
|--------|--------|-------|
| Account age < 30 days | -30 | Major red flag |
| Account age 30–180 days | -15 | Minor flag |
| Repo age < 30 days | -20 | |
| Suspended/deleted contributor | -25 per account | |
| Single commit | -15 | |
| Force-push detected | -20 | Compare pushed_at vs created_at |
| Zero followers | -5 | |
| Repo count < 3 | -5 | |

Start at 100, subtract. Floor at 0.

**Output**: Score + list of triggered signals with explanations

---

### Module 2 — Hook Scanner (`hook_scanner.py`)
**Purpose**: Detect malicious payload delivery via git hooks.
This is the most original contribution of this tool — no existing scanner
covers this vector accessibly.

**Method**:
1. Fetch repo tree (recursive) via Git Trees API
2. Identify any files under `.githooks/`
3. If none found → CLEAN
4. For each hook file:
   - Fetch content
   - Scan for execution patterns (see below)
   - Calculate comment-to-code ratio

**Execution pattern flags** (any match → WARNING or CRITICAL):
- `curl`, `wget` combined with `| sh`, `| bash`, `| cmd`, `| zsh`
- External URLs in shell commands
- `>/dev/null 2>&1` or equivalent output suppression
- `nohup` (persistence indicator)
- Base64 encoded commands

**Comment-to-code ratio heuristic** (novel detection logic):
- Count lines starting with `#` (comments) vs executable lines
- If ratio > 70% comments AND network commands present → flag as suspicious
- Rationale: the FlexPay attack buried 6 lines of payload under 40 lines
  of decoy comments. This is statistically anomalous for a legitimate hook.

**Output**: List of hook files found, flags per file, comment ratio, severity

---

### Module 3 — VS Code Scanner (`vscode_scanner.py`)
**Purpose**: Detect IDE auto-execution configuration.
This attack surface is documented but has no accessible defensive tooling.

**Files inspected**:
- `.vscode/tasks.json`
- `.vscode/settings.json`

**tasks.json flags**:
- `"runOn": "folderOpen"` present → WARNING
- `"runOn": "folderOpen"` + any shell command → CRITICAL
- `"task.allowAutomaticTasks": "on"` in settings.json → WARNING
- Both present together → CRITICAL
- Output suppression in presentation config
  (`reveal: silent`, `echo: false`, `focus: false`) → escalate to CRITICAL

**Context note in output**:
"VS Code 1.109+ (Feb 2026) disables automatic task execution by default.
This configuration would still execute on older versions and may still prompt
on newer versions in ways designed to mislead the user."

**Output**: Files found, flags with exact JSON paths, severity

---

### Module 4 — IOC Extractor (`ioc_extractor.py`)
**Purpose**: Extract indicators of compromise from all text files in the repo.

**Extraction patterns** (regex):
- URLs and domains
- Ethereum/EVM wallet addresses (`0x[a-fA-F0-9]{40}`)
- Base64 blobs (length > 20, valid base64 charset)
- IP addresses

**Base64 handling**:
- Decode any detected base64 blob
- Scan decoded content for the same patterns recursively
- Max recursion depth: 3 (prevents DoS on deeply nested encoding)

**VirusTotal enrichment** (only if `--vt-key` provided):
- Check extracted domains and URLs against VT API
- Free tier: 4 lookups/minute, 500/day — sufficient for MVP
- Output VT reputation score alongside each IOC
- If no key: list IOCs without reputation, note how to add VT enrichment

**Output**: Structured IOC list grouped by type, VT scores if available

---

## Dependency Stack

```toml
[project]
name = "repo-guard"
version = "0.1.0"
description = "CLI security scanner for GitHub repositories"
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "requests>=2.31.0",
    "rich>=13.0.0",
    "click>=8.1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "responses>=0.24.0",
    "ruff>=0.1.0",
]

[project.scripts]
repo-guard = "repo_guard.cli:main"
```

Minimal. No frameworks, no heavy deps. Pure Python 3.10+.

---

## Phase 1: Foundation
**Scope**: `models.py`, `github_client.py`
**Why first**: Everything downstream consumes these types and this API layer.

**Deliverables**:
- `models.py`: `Severity`, `Finding`, `ModuleResult`, `ScanResult` dataclasses
- `github_client.py`: URL parsing, API calls (contents, trees, metadata), error handling

**Quality Gate**:
- `test_models.py`: instantiation, serialization, severity ordering
- `test_github_client.py`: mocked HTTP responses for all API paths, URL parser edge cases, rate limit handling (no live GitHub API calls)
- Run pytest. All tests pass.

**Blocking criteria**: If models can't serialize to JSON or client can't handle 404s/403s, fix before proceeding.

---

## Phase 2: Infrastructure
**Scope**: `reporter.py`, `cli.py` (skeleton)
**Why second**: These produce and consume the model layer; no module logic needed yet.

**Deliverables**:
- `reporter.py`: terminal formatting (rich panels/tables), `--json` output
- `cli.py`: argument parsing (`scan`, `--token`, `--vt-key`, `--json`, `--preview`, `--recruiter`), entry point

**Quality Gate**:
- `test_reporter.py`: render a mock `ScanResult` at each severity level, verify JSON round-trip
- `test_cli.py`: verify argparse/click parses all flags, invalid URLs rejected, help text exists (no live GitHub API calls)
- Run pytest. All tests pass.

**Blocking criteria**: If `--json` produces malformed output or entry point crashes on valid args, fix before proceeding.

---

## Phase 3: Modules
**Scope**: `modules/trust_score.py`, `modules/hook_scanner.py`, `modules/vscode_scanner.py`, `modules/ioc_extractor.py`
**Why third**: Each module is independent once models and github_client exist.

**Deliverables**:
- Trust Score: account/repo heuristics (scoring 0–100)
- Hook Scanner: `.githooks/` detection, execution patterns, comment ratio
- VS Code Scanner: `.vscode/tasks.json` + `settings.json` auto-execution flags
- IOC Extractor: regex extraction, base64 recursion, optional VT enrichment

**Quality Gate**:
- `test_trust_score.py`: known account ages, suspended contributors, force-push indicators (mocked API responses)
- `test_hook_scanner.py`: FlexPay attack fixture (loads `tests/fixtures/flexpay_mock/` from disk, no network), clean hooks, no hooks
- `test_vscode_scanner.py`: `runOn: folderOpen`, task suppression configs, benign configs (loads `tests/fixtures/clean_repo/` from disk)
- `test_ioc_extractor.py`: base64 recursion depth limit, URL/wallet extraction, VT mock responses
- Run pytest. All modules return `ModuleResult` with correct `Severity` for each fixture.

**Blocking criteria**: If FlexPay fixture doesn't trigger CRITICAL/WARNING where expected, fix before proceeding.

---

## Phase 4: Integration & Docs
**Scope**: Full `cli.py` wiring, end-to-end tests, `README.md`, `IOC_FEED.md`
**Why last**: Only safe to wire and test end-to-end when all units are proven.

**Deliverables**:
- `cli.py`: orchestration of all four modules in sequence, `--preview` implementation
- `README.md`: full backstory + usage
- `IOC_FEED.md`: FlexPay entry

**Quality Gate**:
- `test_integration.py`: full scan command with mocked GitHub/VT APIs for happy path, private repo without token, rate limited response, network timeout (no live API calls)
- Run full pytest suite (`pytest -x`). 100% pass rate.

**Blocking criteria**: Integration tests must cover all failure modes in the plan's failure matrix.

---

## Test Fixtures

### `tests/fixtures/flexpay_mock/`
Static replica of the FlexPay attack chain. Loaded from disk in tests. **No network calls.**
- `.githooks/post-checkoput`: 40+ lines of shell comments with 6 lines of payload (curl | bash, output suppression)
- `.vscode/tasks.json`: `runOn: folderOpen` + shell task
- `.vscode/settings.json`: `task.allowAutomaticTasks: on`

This fixture is the canary test. If any module returns CLEAN or fails to flag it, the build is broken.

### `tests/fixtures/clean_repo/`
Benign repo structure used to verify false-negative rate.
- `.vscode/settings.json`: basic editor config, no auto-execution
- `src/main.py`: plain Python file, no IOCs
- No `.githooks/` directory

All modules must return CLEAN for this fixture.

---

## Test Strategy Notes
- **No live API calls in any test** — `responses` library or `unittest.mock` for HTTP. Static fixtures for file-based modules.
- The FlexPay attack chain is a named fixture in Phase 3. It is the canary test.
- Each phase adds test files; previous phase tests must still pass (regression guard).
- Fixtures live on disk and are loaded directly by test functions — they never hit GitHub.

---

## What Ships in MVP

- Module 1 — Trust Score
- Module 2 — Hook Scanner
- Module 3 — VS Code Scanner
- Module 4 — IOC Extractor (with optional VT)
- Safe preview mode (`--preview`)
- Recruiter context flag (`--recruiter`)
- JSON output (`--json`)
- Color terminal output
- README with full backstory
- IOC_FEED.md with FlexPay entry

## What Does Not Ship in MVP

- Ollama/LLM narrative summary (future community contribution)
- Browser extension
- Telegram/Discord bot
- Full typosquatting engine
- Contributor network graph pivot
- Local file scanner mode (`repo-guard scan ./local-repo`)

---

## Design Guardrails

1. **No AI/LLM inference anywhere** — deterministic scoring only.
2. **No cloning** — everything via GitHub API, pre-clone only.
3. **No silent failures** — every edge case must produce a visible finding.
4. **No heavy dependencies** — pure Python 3.10+, three core libs only.
5. **No scraping** — all data from official GitHub APIs.
6. **No post-clone analysis** — this is pre-execution defense, not audit.
7. **No live API calls in tests** — fixtures only, mocked network.

---

*Built the night of the attack. Shipped the morning after.*
