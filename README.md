# repo-guard

**Pre-clone security scanner for GitHub repositories.**  
Built the night I was targeted by a North Korean APT recruitment scam.

> **Note**: VS Code 1.109+ (February 2026) disables automatic task execution
> by default. This tool still matters — older versions remain vulnerable, the
> `.githooks/` vector is unaffected by the patch, and the VS Code fix can be
> socially engineered around via the workspace trust prompt.

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

## The Story

<details>
<summary>Why this tool exists</summary>

A recruiter contacted me on LinkedIn — fake persona, impossible job history,
claimed CEO of a real crypto startup. Offered a paid advisory role and invited
me to review a GitHub repository as the first step. Standard playbook.

Before running anything, I inspected the code manually. What I found:

- `.vscode/tasks.json` configured to silently execute code the moment the
  project opens in VS Code — no prompt, no warning
- `.githooks/post-checkout` downloading and executing a remote payload from
  an external server across Mac, Linux, and Windows simultaneously, all output
  suppressed behind 40 lines of decoy comments
- The project structure designed to have developers enter a wallet private key
  into a local environment file — a standard Web3 pattern that, combined with
  the already-executing payload, would enable direct key exfiltration

The campaign is consistent with documented North Korean Lazarus Group /
Contagious Interview recruitment scams targeting Web3 developers. Reports
were filed with the FBI IC3, RCMP, Vercel, GitHub, LinkedIn, and Basescan.

No existing tool caught this. So I built one.

</details>

## The Gap

Most security tooling focuses on dependencies and known malware signatures.
Nobody was scanning:

- `.vscode/tasks.json` for auto-execution configuration
- `.githooks/` for hidden payload delivery
- Repository metadata for trust signals (account age, suspended contributors,
  force-push history)

These are the exact vectors used in developer-targeted APT campaigns.
`repo-guard` fills that gap. It is not a replacement for Snyk, Socket.dev,
or npm audit — those run after you clone. This runs before.

## How It Works

repo-guard fetches repository metadata via the GitHub API **without cloning**.
It runs four independent modules and produces a color-coded risk report.

| Module | What It Detects |
|--------|----------------|
| **Trust Score** | Account/repo metadata heuristics — age, followers, contributors, force-push indicators |
| **Hook Scanner** | Malicious git hooks in `.githooks/` — execution patterns, base64 payloads, comment-to-code ratio |
| **VS Code Scanner** | Auto-execution configuration in `.vscode/tasks.json` and `.vscode/settings.json` — `runOn: folderOpen`, `allowAutomaticTasks` |
| **IOC Extractor** | Indicators of compromise — URLs, domains, Ethereum addresses, IPs, base64 payloads — with optional VirusTotal enrichment |

## Usage
Usage: repo-guard scan [OPTIONS] GITHUB_URL
Scan a GitHub repository for security risks without cloning.
Options:
--token TEXT     GitHub Personal Access Token (or set REPO_GUARD_TOKEN).
--vt-key TEXT    VirusTotal API key for IOC enrichment (or set REPO_GUARD_VT_KEY).
--json           Output results as JSON.
--preview        Preview suspicious file contents in terminal.
--recruiter TEXT Recruiter context: LinkedIn URL or message text.
--help           Show this message and exit.

### Examples

```bash
# Scan with recruiter context
repo-guard scan https://github.com/owner/repo --recruiter "linkedin.com/in/recruiter"

# Preview flagged files without downloading
repo-guard scan https://github.com/owner/repo --preview

# With VirusTotal enrichment
repo-guard scan https://github.com/owner/repo --vt-key vt_xxxx

# Pipe JSON to jq
repo-guard scan https://github.com/owner/repo --json | jq '.modules[].severity'
```

## Example Output
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
│  • task.allowAutomaticTasks is enabled ("on"). │
│  • Both present — fully automatic execution    │
╰────────────────────────────────────────────────╯
╭─ OVERALL RISK: CRITICAL ───────────────────────╮
╰─────────────────────────────────────────────────╯

## Architecture

Detection is entirely deterministic — scored signals, regex patterns, and
API lookups. No repository contents are sent to external AI APIs.

Public repositories only by default. Private repository scanning requires
a GitHub personal access token (`--token`).

## Limitations

- Not a replacement for a full security audit
- Public repos only without `--token`
- VirusTotal free tier: 500 lookups/day
- `--preview` and `--recruiter` flags are scaffolded, full implementation
  coming in v0.2.0

## Requirements

- Python 3.10+
- `requests`, `rich`, `click` (installed automatically)

## Development

```bash
git clone https://github.com/WBChain3/repo-guard
cd repo-guard
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=repo_guard
```

All tests use mocked HTTP and on-disk fixtures. No live API calls.

## Project Structure
repo_guard/
├── repo_guard/
│   ├── cli.py                  # Entry point, click orchestration
│   ├── github_client.py        # GitHub API client
│   ├── models.py               # Dataclasses: Severity, Finding, ModuleResult, ScanResult
│   ├── reporter.py             # Terminal + JSON output
│   └── modules/
│       ├── trust_score.py      # Module 1: Account & repo metadata
│       ├── hook_scanner.py     # Module 2: .githooks payload detection
│       ├── vscode_scanner.py   # Module 3: .vscode auto-execution detection
│       └── ioc_extractor.py    # Module 4: IOC extraction & VT enrichment
├── tests/
│   ├── fixtures/
│   │   ├── flexpay_mock/       # Attack chain replica (canary test)
│   │   └── clean_repo/         # Benign repo (false-negative guard)
│   ├── conftest.py
│   └── test_*.py
├── ARCHITECT_DECISIONS.md
├── IOC_FEED.md
└── pyproject.toml

## Reported IOCs

See [IOC_FEED.md](IOC_FEED.md) for findings from real-world scans.
Community IOC submissions welcome — open an issue or PR.

## License

MIT