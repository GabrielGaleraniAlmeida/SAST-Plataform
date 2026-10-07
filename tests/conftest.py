import pytest
import ast
from unittest.mock import Mock

@pytest.fixture
def sample_python_code():
    return """
import os
import subprocess
import sqlite3
from flask import request

def get_user():
    user_id = request.args.get('id')
    # Vulnerability: SQL Injection
    cursor = sqlite3.connect('db.sqlite').cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    
def execute_cmd():
    cmd = request.form.get('cmd')
    # Vulnerability: Command Injection
    os.system(cmd)
    
def hardcoded_secrets():
    # Vulnerability: Hardcoded Password
    api_key = "AKIA1234567890ABCDEF"
    db_password = "super_secret_admin_password"
    """

@pytest.fixture
def mock_ast_data(sample_python_code):
    return {"type": "python", "tree": ast.parse(sample_python_code)}
