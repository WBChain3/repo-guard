"""
IOC Extractor Module — Module 4

Extracts indicators of compromise from all text files in the repository.

Extraction patterns:
  - URLs and domains
  - Ethereum/EVM wallet addresses (0x[a-fA-F0-9]{40})
  - Base64 blobs (length > 20, valid base64 charset)
  - IP addresses

Base64 handling:
  - Decode detected base64 blobs
  - Scan decoded content for the same patterns recursively
  - Max recursion depth: 3 (prevents DoS on deeply nested encoding)

VirusTotal enrichment (optional):
  - Check extracted domains and URLs against VT API
  - If no key provided, list IOCs without reputation, note how to add VT
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from repo_guard.github_client import GitHubClient, NotFoundError
from repo_guard.models import Severity, Finding, ModuleResult


# ---------------------------------------------------------------------------
# IOC extraction patterns
# ---------------------------------------------------------------------------

# URL pattern — matches http/https URLs.
URL_PATTERN = re.compile(r"https?://[^\s\"'<>(){}|\\^`\[\]]+")

# Domain pattern — matches registered domains (not IPs).
# We use a blocklist of common JSON key / code identifier TLD-like strings
# to avoid false positives from things like "files.exclude" or "editor.formatOnSave".
DOMAIN_BLOCKLIST = {
    s.lower() for s in {
        "exclude", "formatOnSave", "tabSize", "autoSave", "defaultFormatter",
        "gitignore", "prettier", "vscode", "venv", "pycache", "editor",
        "files", "task", "tasks", "allowAutomaticTasks", "reveal", "panel",
        "group", "label", "type", "command", "runOn", "folderOpen", "presentation",
        "echo", "focus", "description", "problemMatcher", "options", "shell",
        "args", "windows", "linux", "osx", "init", "version", "dedicated",
        "esbenp",
    }
}
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

# Ethereum/EVM wallet address pattern.
ETH_ADDRESS_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# IP address pattern (IPv4).
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Base64-like blob pattern (length > 20, valid base64 charset).
B64_PATTERN = re.compile(r"[A-Za-z0-9+/=]{21,}")

# Common source file extensions — treat these as text.
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".md", ".txt", ".rst", ".html",
    ".css", ".scss", ".less", ".sh", ".bash", ".zsh", ".fish", ".ps1",
    ".bat", ".cmd", ".env", ".xml", ".svg", ".sql", ".rb", ".php",
    ".go", ".rs", ".java", ".kt", ".swift", ".c", ".cpp", ".h", ".hpp",
    ".gradle", ".lock", ".gitignore", ".dockerfile", ".vue", ".svelte",
    ".terraform", ".tf", ".hcl",
}

# File paths that are always text regardless of extension.
ALWAYS_TEXT_PATHS = {
    ".githooks",
    ".vscode",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
}

MAX_BASE64_RECURSION = 3


def _is_text_file(path: str) -> bool:
    """
    Determine whether a file path is likely a text file.

    Checks both the file extension and known text-only path prefixes.
    """
    # Check known text path prefixes.
    for prefix in ALWAYS_TEXT_PATHS:
        if path.startswith(prefix) or path == prefix:
            return True
    # Check file extension.
    ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return ext in TEXT_EXTENSIONS


def _extract_urls(text: str) -> list[str]:
    """Extract unique URLs from text."""
    return sorted(set(URL_PATTERN.findall(text)))


def _extract_domains(text: str) -> list[str]:
    """Extract unique domain names from text, excluding IPs and code identifiers."""
    domains = []
    for match in DOMAIN_PATTERN.finditer(text):
        domain = match.group()
        # Skip if it looks like an IP address.
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            continue
        # Skip if the last part (TLD-like) is in the JSON key blocklist.
        parts = domain.split(".")
        if len(parts) >= 2 and parts[-1].lower() in DOMAIN_BLOCKLIST:
            continue
        # Skip if any part is a single char (unlikely to be real domain).
        if any(len(p) == 1 for p in parts):
            continue
        domains.append(domain)
    return sorted(set(domains))


def _extract_eth_addresses(text: str) -> list[str]:
    """Extract unique Ethereum/EVM wallet addresses."""
    return sorted(set(ETH_ADDRESS_PATTERN.findall(text)))


def _extract_ips(text: str) -> list[str]:
    """Extract unique IP addresses from text."""
    ips = []
    for match in IP_PATTERN.finditer(text):
        ip = match.group()
        # Validate each octet is 0–255.
        octets = ip.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            ips.append(ip)
    return sorted(set(ips))


def _extract_base64_blobs(text: str) -> list[str]:
    """Extract potential base64 blobs (length > 20, valid charset)."""
    blobs = []
    for match in B64_PATTERN.finditer(text):
        b64_str = match.group()
        # Filter by length; pad if needed for decoding.
        if len(b64_str) < 21:
            continue
        # Skip strings that are just hex (look like shas/hashes).
        if re.match(r"^[0-9a-f]{21,}$", b64_str, re.IGNORECASE):
            continue
        try:
            # Try decoding; discard if it fails.
            decoded = base64.b64decode(b64_str, validate=True)
            # Must decode to printable-ish text to be useful.
            # Skip if decoded is very small or contains only binary.
            if len(decoded) > 5 and _is_printable(decoded):
                blobs.append(b64_str)
        except (ValueError, base64.binascii.Error):
            continue
    return blobs


def _is_printable(data: bytes) -> bool:
    """Check if byte data is mostly printable ASCII/UTF-8."""
    try:
        text = data.decode("utf-8")
        # At least 60% printable characters.
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        return printable / max(len(text), 1) >= 0.6
    except UnicodeDecodeError:
        return False


def _decode_base64(text: str, depth: int = 0) -> list[str]:
    """
    Decode base64 blobs and extract IOCs from decoded content recursively.

    Args:
        text: The text to scan.
        depth: Current recursion depth (starts at 0).

    Returns:
        List of decoded strings that contain additional IOCs.
    """
    if depth >= MAX_BASE64_RECURSION:
        return []

    decoded_texts = []
    blobs = _extract_base64_blobs(text)

    for b64_str in blobs:
        try:
            decoded_bytes = base64.b64decode(b64_str, validate=True)
        except (ValueError, base64.binascii.Error):
            continue

        try:
            decoded_str = decoded_bytes.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            continue

        # Only recurse if the decoded content has meaningful text.
        if len(decoded_str.strip()) < 10:
            continue

        decoded_texts.append(decoded_str)

        # Recursively scan the decoded content.
        decoded_texts.extend(_decode_base64(decoded_str, depth + 1))

    return decoded_texts


# ---------------------------------------------------------------------------
# VirusTotal enrichment
# ---------------------------------------------------------------------------

VT_API_URL = "https://www.virustotal.com/api/v3"

VT_ENRICHMENT_NOTE = (
    "VirusTotal enrichment not available. Re-run with --vt-key to check "
    "extracted domains and URLs against VirusTotal."
)


def _enrich_with_virustotal(
    domains: list[str], vt_key: str
) -> dict[str, Any]:
    """
    Check extracted domains against VirusTotal API.

    Returns a dict mapping each domain to its VT reputation data.
    Handles free-tier rate limits gracefully (4 lookups/minute).
    """
    results: dict[str, Any] = {}
    # TODO: Implement real VT API calls.
    # For MVP, this is a placeholder that returns empty results.
    # The actual implementation will check each domain against
    # /api/v3/domains/{domain} with the provided API key.
    return results


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------


def scan(
    client: GitHubClient,
    owner: str,
    repo: str,
    vt_key: str | None = None,
) -> ModuleResult:
    """
    Scan the repository for indicators of compromise.

    Extracts IOCs from all text files in the repo tree, with optional
    VirusTotal enrichment if vt_key is provided.

    Returns a ModuleResult.
    """
    findings: list[Finding] = []
    raw_data: dict[str, Any] = {}

    all_urls: set[str] = set()
    all_domains: set[str] = set()
    all_eth_addresses: set[str] = set()
    all_ips: set[str] = set()
    all_b64_payloads: list[str] = []

    # ------------------------------------------------------------------
    # 1. Fetch the repo tree
    # ------------------------------------------------------------------
    try:
        tree = client.get_tree(owner, repo)
        raw_data["tree_entries_count"] = len(tree)
    except Exception as exc:
        return ModuleResult(
            module_name="ioc_extractor",
            severity=Severity.INFO,
            findings=[
                Finding(
                    message=f"Could not fetch repository tree: {exc}",
                    severity=Severity.INFO,
                    details={"error": str(exc)},
                )
            ],
            raw_data={"error": str(exc)},
        )

    # Filter to text files only.
    text_files = [
        entry["path"] for entry in tree
        if entry.get("type") == "blob"
        and _is_text_file(entry["path"])
    ]
    raw_data["text_files_found"] = len(text_files)

    if not text_files:
        return ModuleResult(
            module_name="ioc_extractor",
            severity=Severity.CLEAN,
            findings=[
                Finding(
                    message="No text files found in repository. No IOCs to extract.",
                    severity=Severity.CLEAN,
                )
            ],
            raw_data=raw_data,
        )

    # ------------------------------------------------------------------
    # 2. Fetch and scan each text file
    # ------------------------------------------------------------------
    files_scanned = 0
    for file_path in sorted(text_files):
        try:
            content = client.get_file_content(owner, repo, file_path)
        except (NotFoundError, Exception):
            continue

        if content is None:
            continue

        files_scanned += 1

        # Extract IOCs from file content.
        all_urls.update(_extract_urls(content))
        all_domains.update(_extract_domains(content))
        all_eth_addresses.update(_extract_eth_addresses(content))
        all_ips.update(_extract_ips(content))

        # Extract and decode base64 blobs recursively.
        decoded_texts = _decode_base64(content)
        all_b64_payloads.extend(decoded_texts)

        # Also scan decoded text for IOCs.
        for decoded in decoded_texts:
            all_urls.update(_extract_urls(decoded))
            all_domains.update(_extract_domains(decoded))
            all_eth_addresses.update(_extract_eth_addresses(decoded))
            all_ips.update(_extract_ips(decoded))

    raw_data["files_scanned"] = files_scanned

    # ------------------------------------------------------------------
    # 3. Compile findings
    # ------------------------------------------------------------------
    ioc_count = sum([
        len(all_urls), len(all_domains), len(all_eth_addresses),
        len(all_ips), len(all_b64_payloads),
    ])
    raw_data["iocs"] = {
        "urls": sorted(all_urls),
        "domains": sorted(all_domains),
        "eth_addresses": sorted(all_eth_addresses),
        "ips": sorted(all_ips),
        "base64_payloads": all_b64_payloads,
    }

    # VirusTotal enrichment (optional).
    if vt_key:
        vt_results = _enrich_with_virustotal(list(all_domains | all_urls), vt_key)
        raw_data["virustotal"] = vt_results
    else:
        raw_data["virustotal"] = {"note": VT_ENRICHMENT_NOTE}

    if ioc_count == 0:
        severity = Severity.CLEAN
        findings.append(Finding(
            message=f"Scanned {files_scanned} text file(s), no IOCs detected.",
            severity=Severity.CLEAN,
            details={"files_scanned": files_scanned},
        ))
    else:
        severity = Severity.WARNING
        finding_messages = []
        if all_urls:
            finding_messages.append(f"{len(all_urls)} URL(s)")
        if all_domains:
            finding_messages.append(f"{len(all_domains)} domain(s)")
        if all_eth_addresses:
            finding_messages.append(f"{len(all_eth_addresses)} Ethereum address(es)")
        if all_ips:
            finding_messages.append(f"{len(all_ips)} IP address(es)")
        if all_b64_payloads:
            finding_messages.append(f"{len(all_b64_payloads)} base64 payload(s)")

        msg = f"Extracted {ioc_count} IOC(s) from {files_scanned} file(s): {', '.join(finding_messages)}."
        findings.append(Finding(
            message=msg,
            severity=severity,
            details={"ioc_count": ioc_count, "files_scanned": files_scanned},
        ))

        if not vt_key:
            findings.append(Finding(
                message=VT_ENRICHMENT_NOTE,
                severity=Severity.INFO,
            ))

    return ModuleResult(
        module_name="ioc_extractor",
        severity=severity,
        findings=findings,
        raw_data=raw_data,
    )
