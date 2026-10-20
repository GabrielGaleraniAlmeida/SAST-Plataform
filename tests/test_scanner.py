"""
Tests for SASTScanner — covers the full scan pipeline:
parser + rules engine + taint analysis.

These tests use scan_snippet() which is the synchronous entry point
(no Git cloning required), making them suitable for unit tests.
"""

import pytest
from services.analyzer.app.engine.scanner import SASTScanner


@pytest.fixture
def scanner():
    return SASTScanner()


# ---------------------------------------------------------------------------
# Basic scan functionality
# ---------------------------------------------------------------------------
def test_scan_snippet_returns_list(scanner):
    """scan_snippet should always return a list (even for empty code)."""
    result = scanner.scan_snippet("", "python", "empty.py")
    assert isinstance(result, list)


def test_scan_snippet_clean_code_no_findings(scanner):
    """Clean Python code should return no findings."""
    code = """
def add(a: int, b: int) -> int:
    return a + b

result = add(1, 2)
"""
    findings = scanner.scan_snippet(code, "python", "clean.py")
    assert findings == [], f"Clean code should yield no findings, got: {findings}"


# ---------------------------------------------------------------------------
# SQL Injection detection (rules engine)
# ---------------------------------------------------------------------------
def test_scan_detects_sql_injection(scanner):
    """SQL injection via f-string should be detected by the rules engine."""
    code = """
import sqlite3
from flask import request

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    findings = scanner.scan_snippet(code, "python", "app.py")
    assert len(findings) > 0, "SQL injection should be detected"

    rule_ids = [f["rule_id"] for f in findings]
    # Either a rules engine finding or a taint finding
    has_sql_finding = any(
        "sql" in r.lower() or "taint" in r.lower() or r == "SAST-002"
        for r in rule_ids
    )
    assert has_sql_finding, f"Should have SQL/taint finding, got rule_ids: {rule_ids}"


# ---------------------------------------------------------------------------
# Command Injection detection (taint analysis)
# ---------------------------------------------------------------------------
def test_scan_detects_command_injection_via_taint(scanner):
    """Command injection from request.args → os.system should be detected via taint."""
    code = """
import os
from flask import request

def run_cmd():
    cmd = request.args.get('cmd')
    os.system(cmd)
"""
    findings = scanner.scan_snippet(code, "python", "handler.py")
    assert len(findings) > 0, "Command injection should be detected"

    taint_findings = [f for f in findings if f.get("rule_id", "").startswith("SAST-TAINT")]
    assert len(taint_findings) > 0, f"Should have taint findings, got: {findings}"


# ---------------------------------------------------------------------------
# Hardcoded secret detection
# ---------------------------------------------------------------------------
def test_scan_detects_hardcoded_secret(scanner):
    """Hardcoded AWS key should be detected."""
    code = 'api_key = "AKIA1234567890ABCDEF"'
    findings = scanner.scan_snippet(code, "python", "config.py")
    assert len(findings) > 0, "Hardcoded secret should be detected"


# ---------------------------------------------------------------------------
# Finding structure validation
# ---------------------------------------------------------------------------
def test_scan_finding_has_required_fields(scanner):
    """Each finding should have all required fields."""
    code = """
import os
from flask import request
cmd = request.args.get('cmd')
os.system(cmd)
"""
    findings = scanner.scan_snippet(code, "python", "handler.py")
    assert len(findings) > 0

    required_fields = {"file_path", "line_number", "rule_id", "severity", "title"}
    for finding in findings:
        missing = required_fields - set(finding.keys())
        assert not missing, f"Finding missing fields: {missing}. Finding: {finding}"


def test_scan_finding_file_path_matches_input(scanner):
    """file_path in findings should match the filename provided."""
    code = "import os\ncmd = input()\nos.system(cmd)\n"
    findings = scanner.scan_snippet(code, "python", "my_script.py")
    assert len(findings) > 0
    for f in findings:
        assert f["file_path"] == "my_script.py", f"Expected 'my_script.py', got '{f['file_path']}'"


def test_taint_finding_includes_flow_metadata(scanner):
    code = (
        "from flask import request\n"
        "import os\n"
        "cmd = request.args.get('cmd')\n"
        "os.system(cmd)\n"
    )
    finding = next(
        f for f in scanner.scan_snippet(code, "python", "handler.py")
        if f["rule_id"] == "SAST-TAINT-001"
    )

    assert finding["taint_metadata"] == {
        "source": "request.args",
        "sink": "os.system",
        "source_line": 3,
        "sink_line": 4,
        "is_sanitized": False,
        "variable": "cmd",
        "function_name": None,
        "intermediates": ["request.args", "cmd"],
    }


def test_scan_directory_returns_sanitized_taint_flows(scanner, tmp_path):
    code = """from flask import request
import os
import shlex

def run():
    raw = request.args.get("cmd")
    safe = shlex.quote(raw)
    os.system("echo " + safe)
"""
    (tmp_path / "app.py").write_text(code, encoding="utf-8")

    result = scanner.scan_directory(str(tmp_path))

    assert len(result["taint_flows"]) == 1
    flow = result["taint_flows"][0]
    assert flow["file_path"] == "app.py"
    assert flow["source_line"] == 6
    assert flow["sink_line"] == 8
    assert flow["is_sanitized"] is True


# ---------------------------------------------------------------------------
# Full pipeline: parser + rules + taint together
# ---------------------------------------------------------------------------
def test_scan_full_pipeline_combines_rules_and_taint(scanner, sample_python_code):
    """Full pipeline should produce findings from both rules engine and taint analysis."""
    findings = scanner.scan_snippet(sample_python_code, "python", "sample.py")
    assert len(findings) > 0, "Sample code should produce findings"

    rule_findings = [f for f in findings if not f["rule_id"].startswith("SAST-TAINT")]
    taint_findings = [f for f in findings if f["rule_id"].startswith("SAST-TAINT")]

    assert len(rule_findings) > 0, "Rules engine should contribute findings"
    assert len(taint_findings) > 0, "Taint analysis should contribute findings"


# ---------------------------------------------------------------------------
# Severity field validation
# ---------------------------------------------------------------------------
def test_scan_findings_severity_values_are_valid(scanner, sample_python_code):
    """All severity values should be from the allowed set."""
    valid_severities = {"critical", "high", "medium", "low", "info"}
    findings = scanner.scan_snippet(sample_python_code, "python", "sample.py")
    for f in findings:
        assert f["severity"] in valid_severities, (
            f"Unexpected severity '{f['severity']}' in finding: {f}"
        )


# ---------------------------------------------------------------------------
# Unknown language
# ---------------------------------------------------------------------------
def test_scan_snippet_unknown_language_no_crash(scanner):
    """Scanning with an unsupported language should not crash."""
    code = "SELECT * FROM users;"
    # The scanner should handle this gracefully (rules may not match, but no exception)
    try:
        findings = scanner.scan_snippet(code, "sql", "query.sql")
        assert isinstance(findings, list)
    except Exception as e:
        pytest.fail(f"scan_snippet raised an exception for unknown language: {e}")
