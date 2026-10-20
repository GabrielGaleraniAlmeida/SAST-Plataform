"""
Tests for TaintAnalyzer — covers 8+ scenarios including:
- Simple SQL Injection taint flow
- Sanitized flow (should be flagged as sanitized, not a vulnerability)
- Taint through intermediate variable
- Taint from request.args to os.system
- Safe code with no taint flows (empty result)
- Indirect taint through binary concatenation
- Taint through data structures (list)
- Extended sources (request.get_json, os.getenv, request.headers)
- Extended sinks (subprocess.check_call, render_template_string, eval)
- Detailed path info (source_line, sink_line, function_name)
"""

import pytest
from services.analyzer.app.engine.taint_analysis import TaintAnalyzer


@pytest.fixture
def analyzer():
    return TaintAnalyzer()


# ---------------------------------------------------------------------------
# Test 1: Simple SQL Injection taint flow
# ---------------------------------------------------------------------------
def test_sql_injection_simple_flow(analyzer):
    """Detect a basic SQL injection: request.args → cursor.execute."""
    code = """
import sqlite3
from flask import request

def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    flows = analyzer.analyze({}, code)
    assert len(flows) > 0, "Should detect at least one taint flow"

    sql_flow = next((f for f in flows if "execute" in f["sink"]), None)
    assert sql_flow is not None, "Should detect taint reaching cursor.execute"
    assert sql_flow["is_sanitized"] is False, "Flow should NOT be sanitized"
    assert sql_flow["variable"] == "user_id"


# ---------------------------------------------------------------------------
# Test 2: Sanitized flow — should be flagged as sanitized
# ---------------------------------------------------------------------------
def test_sanitized_flow_is_flagged(analyzer):
    """A sanitizer is only trusted for its documented, contextual sink."""
    code = """
import os
import shlex
from flask import request

def safe_cmd():
    user_input = request.args.get('cmd')
    safe_input = shlex.quote(user_input)
    os.system("echo " + safe_input)
"""
    flows = analyzer.analyze({}, code)
    assert len(flows) > 0, "Should detect taint flow even when sanitized"
    assert flows[0]["is_sanitized"] is True, "Flow through sanitizer should be marked sanitized"


def test_generic_sanitize_name_does_not_mark_flow_safe(analyzer):
    code = """
import os
from flask import request

def handle():
    value = request.args.get("cmd")
    os.system(sanitize(value))
"""
    flow = analyzer.analyze({}, code)[0]
    assert flow["is_sanitized"] is False


def test_sanitizer_is_not_trusted_for_unrelated_sink(analyzer):
    code = """
import shlex
from flask import request

def handle():
    value = request.args.get("query")
    cursor.execute(shlex.quote(value))
"""
    flow = analyzer.analyze({}, code)[0]
    assert flow["is_sanitized"] is False


def test_source_directly_in_sink_argument(analyzer):
    code = """
import os
from flask import request

def handle():
    os.system(request.args.get("cmd"))
"""
    flow = analyzer.analyze({}, code)[0]
    assert flow["source_line"] == 6
    assert flow["sink_line"] == 6


def test_taint_does_not_cross_function_scopes(analyzer):
    code = """
from flask import request
import os

def read_input():
    value = request.args.get("cmd")

def use_local():
    value = "safe"
    os.system(value)
"""
    assert analyzer.analyze({}, code) == []


def test_interprocedural_resolution_uses_module_functions_not_same_named_methods(analyzer):
    code = """
import os
from flask import request

def execute(value):
    return "constant"

class Commands:
    def execute(value):
        os.system(value)

def handler():
    execute(request.args.get("cmd"))
"""
    assert analyzer.analyze({}, code) == []


def test_positional_and_named_arguments_and_return_chain(analyzer):
    code = """
import os
from flask import request

def wrap(command):
    return command

def execute(*, value):
    os.system(value)

def handler():
    raw = request.args.get("cmd")
    execute(value=wrap(raw))
"""
    flows = analyzer.analyze({}, code)
    flow = next(item for item in flows if item["sink"] == "os.system")
    assert flow["function_name"] == "execute"
    assert flow["source_line"] == 12
    assert flow["sink_line"] == 9
    assert "wrap" in flow["intermediates"]


def test_collection_assignment_and_mutation_propagate_taint(analyzer):
    code = """
import os
from flask import request

def handler():
    raw = request.args.get("cmd")
    values = []
    values.append(raw)
    os.system(values[0])
"""
    flow = analyzer.analyze({}, code)[0]
    assert flow["sink"] == "os.system"
    assert flow["is_sanitized"] is False


def test_dictionary_assignment_and_update_propagate_taint(analyzer):
    code = """
import os
from flask import request

def handler():
    values = {"cmd": request.args.get("cmd")}
    values.update({"other": "constant"})
    os.system(values["cmd"])
"""
    flow = analyzer.analyze({}, code)[0]
    assert flow["sink"] == "os.system"
    assert flow["is_sanitized"] is False


def test_imported_function_internals_are_not_analyzed(analyzer):
    code = """
from external_commands import execute
from flask import request

def handler():
    execute(request.args.get("cmd"))
"""
    assert analyzer.analyze({}, code) == []


def test_call_depth_is_bounded(analyzer):
    layers = "\n".join(
        f"def layer_{index}(value):\n    return layer_{index + 1}(value)"
        for index in range(5)
    )
    code = f"""
import os
from flask import request

{layers}
def layer_5(value):
    os.system(value)

def handler():
    layer_0(request.args.get("cmd"))
"""
    flows = analyzer.analyze({}, code)
    assert flows == []


# ---------------------------------------------------------------------------
# Test 3: Taint through intermediate variable
# ---------------------------------------------------------------------------
def test_taint_through_intermediate_variable(analyzer):
    """Taint should propagate: source → intermediate → sink."""
    code = """
from flask import request
import os

def handle():
    raw = request.form.get('cmd')
    processed = raw
    os.system(processed)
"""
    flows = analyzer.analyze({}, code)
    assert len(flows) > 0, "Should detect taint flow through intermediate variable"

    flow = flows[0]
    assert flow["is_sanitized"] is False
    # Intermediate chain should include 'raw' and 'processed'
    intermediates = flow.get("intermediates", [])
    assert "raw" in intermediates or "processed" in intermediates, (
        f"Intermediate variables should appear in chain, got: {intermediates}"
    )


def test_taint_propagates_to_called_function_parameter(analyzer):
    """A tainted caller argument should reach sinks using a callee parameter."""
    code = """
import os
from flask import request

def execute_command(command):
    os.system(command)

def handler():
    user_command = request.args.get('cmd')
    execute_command(user_command)
"""
    flows = analyzer.analyze({}, code)
    flow = next((item for item in flows if item["sink"] == "os.system"), None)

    assert flow is not None
    assert flow["function_name"] == "execute_command"
    assert flow["source_line"] == 9
    assert flow["sink_line"] == 6
    assert "command" in flow["intermediates"]


# ---------------------------------------------------------------------------
# Test 4: Taint from request.args to os.system
# ---------------------------------------------------------------------------
def test_request_args_to_os_system(analyzer, sample_python_code):
    """Taint from request.args/form should be detected flowing into os.system."""
    flows = analyzer.analyze({}, sample_python_code)
    assert len(flows) > 0

    cmd_flow = next(
        (f for f in flows if f["sink"] == "os.system"),
        None,
    )
    assert cmd_flow is not None, "Should detect taint reaching os.system"
    assert cmd_flow["is_sanitized"] is False


# ---------------------------------------------------------------------------
# Test 5: Safe code with no taint flows
# ---------------------------------------------------------------------------
def test_safe_code_no_taint_flows(analyzer):
    """Code with no sources or no paths to sinks should return empty list."""
    code = """
def add(a, b):
    return a + b

result = add(1, 2)
print(result)
"""
    flows = analyzer.analyze({}, code)
    assert flows == [], f"Safe code should produce no taint flows, got: {flows}"


# ---------------------------------------------------------------------------
# Test 6: Indirect taint through binary concatenation
# ---------------------------------------------------------------------------
def test_indirect_taint_binary_concat(analyzer):
    """var_a = tainted_b + 'literal' → var_a is also tainted."""
    code = """
from flask import request
import os

def build_cmd():
    user = request.args.get('user')
    cmd = "ls /home/" + user
    os.system(cmd)
"""
    flows = analyzer.analyze({}, code)
    assert len(flows) > 0, "Binary concatenation should propagate taint"

    flow = next((f for f in flows if f["sink"] == "os.system"), None)
    assert flow is not None
    assert flow["is_sanitized"] is False
    # 'cmd' should appear in the chain as it holds the concatenated value
    assert "cmd" in flow.get("intermediates", []) or flow["variable"] == "user"


# ---------------------------------------------------------------------------
# Test 7: Taint through list (data structure)
# ---------------------------------------------------------------------------
def test_taint_through_list_structure(analyzer):
    """Taint contained in a list should propagate to sinks."""
    code = """
from flask import request
import subprocess

def run():
    arg = request.args.get('arg')
    args_list = [arg]
    subprocess.run(args_list)
"""
    flows = analyzer.analyze({}, code)
    assert len(flows) > 0, "Taint through list should be detected"
    flow = next((f for f in flows if "subprocess" in f["sink"] or "run" in f["sink"]), None)
    assert flow is not None


# ---------------------------------------------------------------------------
# Test 8: Extended source — request.get_json()
# ---------------------------------------------------------------------------
def test_extended_source_request_get_json(analyzer):
    """request.get_json() should be recognized as a taint source."""
    code = """
from flask import request
import os

def api_handler():
    data = request.get_json()
    os.system(data)
"""
    flows = analyzer.analyze({}, code)
    assert len(flows) > 0, "request.get_json() should be a recognized source"
    assert flows[0]["is_sanitized"] is False


# ---------------------------------------------------------------------------
# Test 9: Extended source — os.getenv
# ---------------------------------------------------------------------------
def test_extended_source_os_getenv(analyzer):
    """os.getenv() should be recognized as a taint source."""
    code = """
import os

def run_task():
    cmd = os.getenv('USER_CMD')
    os.system(cmd)
"""
    flows = analyzer.analyze({}, code)
    assert len(flows) > 0, "os.getenv should be a recognized taint source"
    flow = next((f for f in flows if f["sink"] == "os.system"), None)
    assert flow is not None
    assert flow["is_sanitized"] is False


# ---------------------------------------------------------------------------
# Test 10: Extended sink — eval
# ---------------------------------------------------------------------------
def test_extended_sink_eval(analyzer):
    """eval() should be recognized as a dangerous sink."""
    code = """
from flask import request

def execute():
    expr = request.args.get('expr')
    result = eval(expr)
"""
    flows = analyzer.analyze({}, code)
    assert len(flows) > 0, "eval() should be a recognized sink"
    flow = next((f for f in flows if f["sink"] == "eval"), None)
    assert flow is not None
    assert flow["is_sanitized"] is False


# ---------------------------------------------------------------------------
# Test 11: Detailed path information
# ---------------------------------------------------------------------------
def test_detailed_path_information(analyzer):
    """Flow dict should contain source_line, sink_line, function_name."""
    code = """
from flask import request
import os

def my_handler():
    user_cmd = request.args.get('cmd')
    os.system(user_cmd)
"""
    flows = analyzer.analyze({}, code)
    assert len(flows) > 0

    flow = flows[0]
    assert "source_line" in flow, "Flow should contain source_line"
    assert "sink_line" in flow, "Flow should contain sink_line"
    assert "function_name" in flow, "Flow should contain function_name"
    assert isinstance(flow["source_line"], int)
    assert isinstance(flow["sink_line"], int)
    assert flow["source_line"] < flow["sink_line"], "Source should come before sink"
    assert flow["function_name"] == "my_handler"


# ---------------------------------------------------------------------------
# Test 12: Syntax error returns empty list (no crash)
# ---------------------------------------------------------------------------
def test_syntax_error_returns_empty(analyzer):
    """SyntaxError in source code should return empty list, not raise."""
    code = "def broken(:\n    pass"
    flows = analyzer.analyze({}, code)
    assert flows == [], "Syntax errors should yield empty taint flow list"


# ---------------------------------------------------------------------------
# Test 13: Extended sink — subprocess.check_call
# ---------------------------------------------------------------------------
def test_extended_sink_subprocess_check_call(analyzer):
    """subprocess.check_call should be a recognized sink."""
    code = """
from flask import request
import subprocess

def run_check():
    cmd = request.form.get('cmd')
    subprocess.check_call(cmd, shell=True)
"""
    flows = analyzer.analyze({}, code)
    assert len(flows) > 0, "subprocess.check_call should be a recognized sink"


# ---------------------------------------------------------------------------
# Test 14: request.headers as source
# ---------------------------------------------------------------------------
def test_extended_source_request_headers(analyzer):
    """request.headers should be recognized as a taint source."""
    code = """
from flask import request
import os

def handle():
    agent = request.headers.get('User-Agent')
    os.system(agent)
"""
    flows = analyzer.analyze({}, code)
    assert len(flows) > 0, "request.headers should be a recognized source"
