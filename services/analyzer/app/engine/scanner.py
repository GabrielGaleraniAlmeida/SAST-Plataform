"""Scanner: clones repos, discovers files and runs parser, rules and taint analysis."""

import logging
import os
import tempfile
from typing import Any, Dict, List

import git

from app.engine.parser import ASTParser
from app.engine.rules import RulesEngine
from app.engine.taint_analysis import TaintAnalyzer

logger = logging.getLogger(__name__)

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__"}


def _flat(f, filename: str) -> Dict[str, Any]:
    """Flatten a rules Finding into the dict format consumed by the API."""
    return {
        "file_path": filename,
        "line_number": f.location.line_start,
        "column": f.location.col_start,
        "rule_id": f.rule_id,
        "rule_name": f.rule_name,
        "severity": f.severity.value,
        "cwe_id": f.cwe_id,
        "title": f.rule_name,
        "description": f.description,
        "code_snippet": f.location.snippet,
        "confidence": f.confidence,
        "language": f.language,
    }


class SASTScanner:
    def __init__(self):
        self.parser = ASTParser()
        self.rules_engine = RulesEngine()
        self.taint_analyzer = TaintAnalyzer()

    def scan_repository(self, repo_url: str, branch: str, language: str = "auto") -> Dict[str, Any]:
        with tempfile.TemporaryDirectory() as tmp:
            logger.info("Cloning %s (%s)", repo_url, branch)
            git.Repo.clone_from(repo_url, tmp, branch=branch, depth=1)
            return self.scan_directory(tmp, language)

    def scan_directory(self, directory: str, language: str = "auto") -> Dict[str, Any]:
        vulnerabilities: List[Dict[str, Any]] = []
        files: List[Dict[str, Any]] = []
        for root, dirs, names in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in names:
                path = os.path.join(root, name)
                lang = self.parser.get_language(path)
                if lang == "unknown" or (language != "auto" and lang != language):
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    code = fh.read()
                rel = os.path.relpath(path, directory).replace(os.sep, "/")
                found = self.scan_snippet(code, lang, rel)
                vulnerabilities.extend(found)
                files.append({
                    "file_path": rel,
                    "language": lang,
                    "lines_of_code": code.count("\n") + 1,
                    "vulnerabilities_count": len(found),
                })
        return {"vulnerabilities": vulnerabilities, "files": files, "total_files": len(files)}

    def scan_snippet(self, code: str, language: str, filename: str = "snippet.py") -> List[Dict[str, Any]]:
        ast_data = self.parser.parse_code(code, language)
        findings = [
            _flat(f, filename)
            for f in self.rules_engine.check_all(ast_data, code, language, filename)
        ]
        if language == "python":
            for flow in self.taint_analyzer.analyze(ast_data, code):
                if flow["is_sanitized"]:
                    continue
                findings.append({
                    "file_path": filename,
                    "line_number": flow["path"][-1],
                    "rule_id": "SAST-TAINT-001",
                    "rule_name": "Fluxo de Dados Não Sanitizado",
                    "severity": "critical",
                    "cwe_id": "CWE-20",
                    "title": f"Tainted flow to {flow['sink']}",
                    "description": f"Input inseguro atinge a função '{flow['sink']}' sem sanitização prévia.",
                    "code_snippet": f"{flow['variable']} -> {flow['sink']}()",
                    "language": language,
                })
        return findings
