import pytest
from services.analyzer.app.engine.taint_analysis import TaintAnalyzer
import ast

def test_taint_analysis_detects_flow(sample_python_code):
    analyzer = TaintAnalyzer()
    ast_data = {"type": "python"}
    flows = analyzer.analyze(ast_data, sample_python_code)
    
    assert len(flows) > 0
    
    # Valida fluxo de command injection
    cmd_flow = next((f for f in flows if f['sink'] == 'os.system' or f['sink'] == 'system'), None)
    assert cmd_flow is not None
    assert cmd_flow['is_sanitized'] is False

def test_sanitized_flow_is_flagged():
    code = """
import os
from flask import request
def safe_cmd():
    user_input = request.args.get('cmd')
    safe_input = sanitize(user_input)
    os.system(safe_input)
"""
    analyzer = TaintAnalyzer()
    flows = analyzer.analyze({"type": "python"}, code)
    assert len(flows) > 0
    assert flows[0]['is_sanitized'] is True
