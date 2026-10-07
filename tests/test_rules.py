from pathlib import Path

import pytest
from services.analyzer.app.engine.rules import RulesEngine
from services.analyzer.app.engine.parser import ASTParser


def scan_python(code, filename="test.py"):
    parser = ASTParser()
    parsed = parser.parse_code(code, "python")
    return RulesEngine().check_all(parsed, code, "python", filename)

def test_hardcoded_password_detection(sample_python_code):
    engine = RulesEngine()
    findings = engine.check_all({"type": "python"}, sample_python_code, "python")
    
    # Verifica se a regra de hardcoded password detectou a violação
    hardcoded_findings = [f for f in findings if f.rule_id == "SAST-001" or getattr(f, 'rule_id', '') == "SAST-001"]
    assert len(hardcoded_findings) >= 1
    assert any("db_password" in (f.location.snippet or "") for f in hardcoded_findings)

def test_sql_injection_detection(sample_python_code):
    engine = RulesEngine()
    findings = engine.check_all({"type": "python"}, sample_python_code, "python")
    
    sql_findings = [f for f in findings if f.rule_id == "SAST-002" or getattr(f, 'rule_id', '') == "SAST-002"]
    assert len(sql_findings) >= 1

def test_command_injection_detection(sample_python_code):
    engine = RulesEngine()
    findings = engine.check_all({"type": "python"}, sample_python_code, "python")
    
    cmd_findings = [f for f in findings if f.rule_id == "SAST-003" or getattr(f, 'rule_id', '') == "SAST-003"]
    assert len(cmd_findings) >= 1


def test_secure_sample_has_no_false_positives_for_refined_rules():
    secure_code = (Path(__file__).parent.parent / "sample_targets" / "secure_app.py").read_text(encoding="utf-8")
    findings = scan_python(secure_code, "secure_app.py")
    assert findings == []


def test_sql_rule_flags_dynamic_query_but_not_constant_or_parameterized_sql():
    code = '''
cursor.execute("SELECT * FROM users WHERE active = 1")
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
    findings = scan_python(code)
    sql_findings = [finding for finding in findings if finding.rule_id == "SAST-002"]
    assert len(sql_findings) == 1
    assert sql_findings[0].location.line_start == 4


def test_command_rule_ignores_docstrings_and_safe_subprocess_calls():
    code = '''
def documented():
    """Example only: os.system(command) and subprocess.run(command, shell=True)."""
    subprocess.run(["ping", host], shell=False)
    os.system(command)
'''
    findings = scan_python(code)
    command_findings = [finding for finding in findings if finding.rule_id == "SAST-003"]
    assert len(command_findings) == 1
    assert command_findings[0].location.line_start == 5


def test_ip_rule_ignores_private_addresses_but_flags_public_literals():
    code = '''
private_host = "192.168.1.10"
public_host = "8.8.8.8"
'''
    findings = scan_python(code)
    ip_findings = [finding for finding in findings if finding.rule_id == "SAST-005"]
    assert len(ip_findings) == 1
    assert ip_findings[0].metadata["ip"] == "8.8.8.8"


def test_auth_rule_only_flags_privileged_routes():
    code = '''
@app.route("/health")
def health():
    return "ok"

@app.route("/admin/users")
def admin_users():
    return "users"
'''
    findings = scan_python(code)
    auth_findings = [finding for finding in findings if finding.rule_id == "SAST-014"]
    assert len(auth_findings) == 1
    assert auth_findings[0].metadata["function"] == "admin_users"


def test_eval_rule_ignores_documentation_and_flags_executable_calls():
    code = '''
"""Do not use eval(user_input)."""
def run(value):
    return eval(value)
'''
    findings = scan_python(code)
    eval_findings = [finding for finding in findings if finding.rule_id == "SAST-006"]
    assert len(eval_findings) == 1
    assert eval_findings[0].location.line_start == 4


def test_ssrf_rule_flags_direct_user_url():
    findings = scan_python('requests.get(request.args.get("url"))')
    assert any(finding.rule_id == "SAST-012" for finding in findings)


def test_sensitive_logging_rule_flags_secret_variables():
    findings = scan_python('logger.info("access token: %s", access_token)')
    assert any(finding.rule_id == "SAST-015" for finding in findings)
