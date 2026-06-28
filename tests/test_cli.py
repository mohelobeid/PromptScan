"""Tests for the command-line interface."""

import promptscan.cli as cli_module
from click.testing import CliRunner

from promptscan.cli import cli


class _FakeEngine:
    """Stand-in for AttackEngine returning a canned (vulns, metadata) tuple."""

    result = ([], {})

    def __init__(self, config):
        self.config = config

    async def run_scan(self):
        return self._result


def _patch_engine(monkeypatch, result):
    fake = type("FakeEngine", (_FakeEngine,), {"_result": result})
    monkeypatch.setattr(cli_module, "AttackEngine", fake)


def test_failed_scan_exits_nonzero_without_clean_report(monkeypatch):
    """A scan that cannot run must not print a misleading 'safe' report."""
    _patch_engine(monkeypatch, ([], {"error": "Connection failed"}))

    runner = CliRunner()
    result = runner.invoke(cli, ["test", "http://unreachable.invalid/chat"])

    # Must signal failure, not success.
    assert result.exit_code == 2
    # Must not claim the target is well-protected.
    assert "MINIMAL RISK" not in result.output
    assert "Connection failed" in result.output


def test_successful_scan_with_no_vulnerabilities_exits_zero(monkeypatch):
    """A completed scan with no findings is a genuine clean result."""
    _patch_engine(
        monkeypatch,
        ([], {"total_payloads": 36, "categories_tested": 6}),
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["test", "http://127.0.0.1/chat"])

    assert result.exit_code == 0
    assert "PROMPTSCAN SECURITY ASSESSMENT REPORT" in result.output


def test_info_command_reports_correct_payload_count():
    runner = CliRunner()
    result = runner.invoke(cli, ["info"])

    assert result.exit_code == 0
    assert "36" in result.output
