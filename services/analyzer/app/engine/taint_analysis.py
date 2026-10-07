"""Taint analysis: tracks untrusted data from sources to dangerous sinks (Python, stdlib ast)."""

import ast
from typing import Any, Dict, List, Optional


def _dotted(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


class TaintAnalyzer:
    SOURCES = {"request.args", "request.form", "request.json", "input", "sys.argv", "os.environ"}
    SINKS = {"cursor.execute", "os.system", "subprocess.run", "subprocess.Popen", "eval", "exec", "open", "render_template"}
    SANITIZERS = {"escape", "quote", "sanitize", "validate", "int", "float"}

    def analyze(self, ast_data: dict, source_code: str) -> List[Dict[str, Any]]:
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []
        nodes = sorted(
            (n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.Call))),
            key=lambda n: (n.lineno, n.col_offset),
        )
        flows: List[Dict[str, Any]] = []
        for var, source in self._sources(nodes).items():
            tainted = {var: False}  # name -> already sanitized?
            for node in nodes:
                if node.lineno <= source.lineno:
                    continue
                if isinstance(node, ast.Assign):
                    state = self._state(node.value, tainted)
                    if state is not None:
                        for t in node.targets:
                            if isinstance(t, ast.Name):
                                tainted[t.id] = state
                elif _dotted(node.func) in self.SINKS:
                    states = [self._state(a, tainted) for a in node.args]
                    states = [s for s in states if s is not None]
                    if states:
                        flows.append({
                            "source": "Untrusted Input",
                            "sink": _dotted(node.func),
                            "path": [source.lineno, node.lineno],
                            "is_sanitized": all(states),
                            "variable": var,
                        })
        return flows

    def _sources(self, nodes: List[ast.AST]) -> Dict[str, ast.Assign]:
        found: Dict[str, ast.Assign] = {}
        for node in nodes:
            if not isinstance(node, ast.Assign):
                continue
            value = node.value
            if isinstance(value, ast.Subscript):
                value = value.value
            if isinstance(value, ast.Call):
                value = value.func
            name = _dotted(value)
            if name and any(src in name for src in self.SOURCES):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        found[t.id] = node
        return found

    def _state(self, expr: ast.AST, tainted: Dict[str, bool]) -> Optional[bool]:
        """None: expression holds no tainted data; True: only sanitized data; False: tainted."""
        if isinstance(expr, ast.Name):
            return tainted.get(expr.id)
        states = [s for s in (self._state(c, tainted) for c in ast.iter_child_nodes(expr)) if s is not None]
        if not states:
            return None
        if isinstance(expr, ast.Call) and (_dotted(expr.func) or "").split(".")[-1] in self.SANITIZERS:
            return True
        return all(states)
