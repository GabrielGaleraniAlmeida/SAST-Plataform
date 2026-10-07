import pytest
from services.analyzer.app.engine.parser import ASTParser

def test_parse_python_code():
    parser = ASTParser()
    code = "def hello():\n    print('world')"
    ast_data = parser.parse_python(code)
    
    assert ast_data is not None
    assert ast_data["language"] == "python"
    assert ast_data["nodes"]

def test_get_language():
    parser = ASTParser()
    assert parser.get_language("file.py") == "python"
    assert parser.get_language("app.js") == "javascript"
    assert parser.get_language("Main.java") == "java"
    assert parser.get_language("unknown.txt") == "unknown"
