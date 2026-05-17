# repo-guard

**Pre-clone security scanner for GitHub repositories.**

Inspect repositories for malicious IDE configuration, git hooks, and suspicious metadata **before you clone**. No AI, no cloning, no heavy dependencies — pure Python 3.10+.

Built in response to a real North Korean APT (Lazarus Group / Contagious Interview) recruitment scam that weaponized `.vscode/tasks.json` and `.githooks/` to achieve code execution on victim machines. No existing tool covers this attack surface.

## Quick Start

```bash
pip install repo-guard

# Scan a public repository
repo-guard scan https://github.com/owner/repo

# With a GitHub token for higher rate limits or private repos
repo-guard scan https://github.com/owner/repo --token ghp_xxxx

# Machine-readable JSON output
repo-guard scan https://github.com/owner/repo --json
```

## Usage

```
Usage: repo-guard scan [OPTIONS] GITHUB_URL

  Scan a GitHub repository for security risks without cloning.

  GITHUB_URL should be a full GitHub repository URL, e.g.:
  https://github.com/owner/repo

Options:
  --token TEXT     GitHub Personal Access Token (or set REPO_GUARD_TOKEN env var).
  --vt-key TEXT    VirusTotal API key for IOC enrichment (or set REPO_GUARD_VT_KEY env var).
  --json           Output results as JSON (machine-readable).
  --preview        Preview suspicious file contents in the terminal.
  --recruiter TEXT Recruiter context: LinkedIn URL or text (for social engineering flag).
  --help           Show this message and exit.
```

### Examples

```bash
# Basic scan with color output
repo-guard scan https://github.com/suspicious/repo

# Private repo scan
repo-guard scan https://github.com/org/private-repo --token ghp_xxxx

# With VirusTotal enrichment
repo-guard scan https://github.com/suspicious/repo --vt-key vt_xxxx

# Pipe JSON output to jq for analysis
repo-guard scan https://github.com/suspicious/repo --json | jq '.modules[].severity'

# Preview flagged files interactively
repo-guard scan https://github.com/suspicious/repo --preview

# Recruiter context flag (documents social engineering vector)
repo-guard scan https://github.com/suspicious/repo --recruiter "https://linkedin.com/in/recruiter"
```

## How It Works

repo-guard fetches repository metadata via the GitHub API **without cloning**. It runs four independent modules and produces a color-coded risk report.

| Module | What It Detects |
|--------|----------------|
| **Trust Score** | Account/repo metadata heuristics — age, followers, contributors, force-push indicators |
| **Hook Scanner** | Malicious git hooks in `.githooks/` — execution patterns, base64 payloads, comment-to-code ratio |
| **VS Code Scanner** | Auto-execution configuration in `.vscode/tasks.json` and `.vscode/settings.json` — `runOn: folderOpen`, `allowAutomaticTasks` |
| **IOC Extractor** | Indicators of compromise — URLs, domains, Ethereum addresses, IPs, base64 payloads — with optional VirusTotal enrichment |

## The Attack

In late 2024, Lazarus Group operatives posed as Web3 recruiters on LinkedIn, sending targets a GitHub repository URL. The repo appeared to contain legitimate payment infrastructure code. Hidden inside:

- **`.vscode/tasks.json`** — configured `"runOn": "folderOpen"` with a shell command that downloaded and executed a payload. Output was suppressed (`reveal: silent`, `echo: false`, `focus: false`).
- **`.vscode/settings.json`** — enabled `"task.allowAutomaticTasks": "on"`, removing VS Code's consent prompt.
- **`.githooks/post-checkout`** — 40 lines of decoy comments concealing `curl | bash`, base64-encoded commands, and nohup persistence.

Opening the repo in VS Code was enough to lose your machine. repo-guard catches all of these signals **before you clone**.

## Output

```
╭──────────────────────────────────────────╮
│ repo-guard scan results                   │
│ https://github.com/suspicious/repo        │
│ Scanned at: 2026-05-17T12:00:00+00:00    │
╰──────────────────────────────────────────╯

╭─ Module: Trust Score  [INFO] ──────────────────╮
│  • Account age is 14 days (< 30).              │
│  • Repository age is 5 days (< 30).            │
╰────────────────────────────────────────────────╯

╭─ Module: Hook Scanner  [CRITICAL] ─────────────╮
│  • Network command with external URL           │
│    file: .githooks/post-checkout               │
│    url: https://evil.com/init.sh               │
│  • Output suppression (>/dev/null 2>&1)        │
│  • Base64 blob decodes to executable payload   │
╰────────────────────────────────────────────────╯

╭─ Module: VS Code Scanner  [CRITICAL] ──────────╮
│  • Task 'Init environment' has runOn: folderOpen│
│  • task.allowAutomaticTasks is enabled ("on").  │
│  • Both present — fully automatic execution     │
╰────────────────────────────────────────────────╯

╭─ OVERALL RISK: CRITICAL ───────────────────────╮
│                                                 │
╰─────────────────────────────────────────────────╯
```

## Requirements

- Python 3.10+
- `requests`, `rich`, `click` (installed automatically)

## Development

```bash
git clone https://github.com/repo-guard/repo-guard
cd repo-guard
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=repo_guard
```

All tests use mocked HTTP and on-disk fixtures. No live API calls.

## Project Structure

```
repo_guard/
├── repo_guard/
│   ├── cli.py                  # Entry point, click orchestration
│   ├── github_client.py        # GitHub API client (single source of truth)
│   ├── models.py               # Dataclasses: Severity, Finding, ModuleResult, ScanResult
│   ├── reporter.py             # Terminal + JSON output (rich)
│   └── modules/
│       ├── trust_score.py      # Module 1: Account & repo metadata
│       ├── hook_scanner.py     # Module 2: .githooks payload detection
│       ├── vscode_scanner.py   # Module 3: .vscode auto-execution detection
│       └── ioc_extractor.py    # Module 4: IOC extraction & VT enrichment
├── tests/
│   ├── fixtures/
│   │   ├── flexpay_mock/       # FlexPay attack chain (canary fixture)
│   │   └── clean_repo/         # Benign repo (false-negative guard)
│   ├── conftest.py             # Shared test helpers
│   └── test_*.py               # One test file per module + integration
├── pyproject.toml
├── README.md
└── IOC_FEED.md
```

## License

MIT
