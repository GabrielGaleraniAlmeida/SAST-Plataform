"""
SAST Analyzer Service - Multi-Language AST Parser

Provides AST parsing for Python (via stdlib ast module) and
JavaScript/Java (via tree-sitter). Normalizes parse output into
a unified dict structure consumed by the rules engine and taint analyzer.
"""

from __future__ import annotations

import ast
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Language Extension Map
# ---------------------------------------------------------------------------

EXTENSION_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
}

# ---------------------------------------------------------------------------
# Unified AST Node Structure
# ---------------------------------------------------------------------------
# Each node dict has:
#   type:        str  - node type label (e.g. "FunctionDef", "Import", "Call")
#   name:        str  - identifier name where applicable
#   value:       Any  - literal value where applicable
#   lineno:      int  - 1-indexed starting line
#   col_offset:  int  - column offset
#   end_lineno:  int  - 1-indexed ending line (optional)
#   children:    list - child node dicts
#   raw:         str  - raw source text of this node (optional)


class PythonASTVisitor(ast.NodeVisitor):
    """
    Walks a Python AST and extracts structured information about
    functions, classes, imports, assignments, calls, and more.
    """

    def __init__(self, source_lines: List[str]) -> None:
        self.source_lines = source_lines
        self.nodes: List[Dict[str, Any]] = []
        self._scope_stack: List[str] = []  # Track enclosing scope names

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_snippet(self, node: ast.AST) -> str:
        """Extract the source line(s) for a node."""
        try:
            start = getattr(node, "lineno", 1) - 1
            end = getattr(node, "end_lineno", start + 1)
            return "\n".join(self.source_lines[start:end]).strip()
        except Exception:
            return ""

    def _node_base(self, node: ast.AST, node_type: str, **extra) -> Dict[str, Any]:
        return {
            "type": node_type,
            "lineno": getattr(node, "lineno", 0),
            "col_offset": getattr(node, "col_offset", 0),
            "end_lineno": getattr(node, "end_lineno", None),
            "end_col_offset": getattr(node, "end_col_offset", None),
            "scope": list(self._scope_stack),
            "snippet": self._get_snippet(node),
            **extra,
        }

    @staticmethod
    def _name_from_node(node: ast.AST) -> str:
        """Best-effort extraction of a name/value string from a node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{PythonASTVisitor._name_from_node(node.value)}.{node.attr}"
        if isinstance(node, ast.Constant):
            return repr(node.value)
        if isinstance(node, ast.Call):
            return f"{PythonASTVisitor._name_from_node(node.func)}()"
        return ast.dump(node)[:60]

    @staticmethod
    def _value_str(node: ast.AST) -> Optional[str]:
        """Return string representation of a value node, or None."""
        if isinstance(node, ast.Constant):
            return str(node.value)
        if isinstance(node, ast.JoinedStr):
            return "<f-string>"
        if isinstance(node, (ast.Name, ast.Attribute)):
            return PythonASTVisitor._name_from_node(node)
        return None

    # ------------------------------------------------------------------
    # Visitor Methods
    # ------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        args = [arg.arg for arg in node.args.args]
        decorators = [self._name_from_node(d) for d in node.decorator_list]
        self.nodes.append(
            self._node_base(
                node,
                "FunctionDef",
                name=node.name,
                args=args,
                decorators=decorators,
                is_async=False,
            )
        )
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        args = [arg.arg for arg in node.args.args]
        decorators = [self._name_from_node(d) for d in node.decorator_list]
        self.nodes.append(
            self._node_base(
                node,
                "FunctionDef",
                name=node.name,
                args=args,
                decorators=decorators,
                is_async=True,
            )
        )
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        bases = [self._name_from_node(b) for b in node.bases]
        decorators = [self._name_from_node(d) for d in node.decorator_list]
        self.nodes.append(
            self._node_base(
                node,
                "ClassDef",
                name=node.name,
                bases=bases,
                decorators=decorators,
            )
        )
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self.nodes.append(
                self._node_base(
                    node,
                    "Import",
                    name=alias.name,
                    alias=alias.asname,
                )
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        for alias in node.names:
            self.nodes.append(
                self._node_base(
                    node,
                    "ImportFrom",
                    module=module,
                    name=alias.name,
                    alias=alias.asname,
                    full_name=f"{module}.{alias.name}",
                )
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        targets = [self._name_from_node(t) for t in node.targets]
        value_str = self._value_str(node.value)
        value_type = type(node.value).__name__

        # Detect string constant assignments
        raw_value: Optional[str] = None
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            raw_value = node.value.value

        self.nodes.append(
            self._node_base(
                node,
                "Assign",
                targets=targets,
                value=value_str,
                value_type=value_type,
                raw_value=raw_value,
            )
        )
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        self.nodes.append(
            self._node_base(
                node,
                "AugAssign",
                target=self._name_from_node(node.target),
                value=self._value_str(node.value),
            )
        )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        value_str = self._value_str(node.value) if node.value else None
        raw_value: Optional[str] = None
        if node.value and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            raw_value = node.value.value

        self.nodes.append(
            self._node_base(
                node,
                "AnnAssign",
                target=self._name_from_node(node.target),
                annotation=self._name_from_node(node.annotation),
                value=value_str,
                raw_value=raw_value,
            )
        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func_name = self._name_from_node(node.func)
        args = [self._value_str(a) or self._name_from_node(a) for a in node.args]

        # Capture keyword arguments as a dict
        kwargs: Dict[str, Optional[str]] = {}
        for kw in node.keywords:
            if kw.arg:
                kwargs[kw.arg] = self._value_str(kw.value) or self._name_from_node(kw.value)

        self.nodes.append(
            self._node_base(
                node,
                "Call",
                func=func_name,
                args=args,
                kwargs=kwargs,
            )
        )
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:  # noqa: N802
        # Capture top-level expressions (e.g., string literals used as docstrings)
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            self.nodes.append(
                self._node_base(node, "StringExpr", value=node.value.value)
            )
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
        value_str = self._value_str(node.value) if node.value else None
        self.nodes.append(self._node_base(node, "Return", value=value_str))
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        self.nodes.append(
            self._node_base(
                node,
                "If",
                test=self._name_from_node(node.test),
            )
        )
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:  # noqa: N802
        items = [self._name_from_node(item.context_expr) for item in node.items]
        self.nodes.append(self._node_base(node, "With", context_managers=items))
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:  # noqa: N802
        self.nodes.append(self._node_base(node, "Global", names=node.names))
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:  # noqa: N802
        exc = self._name_from_node(node.exc) if node.exc else None
        self.nodes.append(self._node_base(node, "Raise", exc=exc))
        self.generic_visit(node)


class ASTParser:
    """
    Multi-language AST parser. Supports Python natively (stdlib ast)
    and JavaScript/Java via tree-sitter.
    """

    def __init__(self) -> None:
        self._ts_parsers: Dict[str, Any] = {}
        self._init_tree_sitter()

    # ------------------------------------------------------------------
    # Tree-sitter Initialization
    # ------------------------------------------------------------------

    def _init_tree_sitter(self) -> None:
        """Attempt to initialise tree-sitter parsers for JS/Java."""
        try:
            import tree_sitter  # type: ignore

            # Try to load grammars if available
            try:
                from tree_sitter import Language, Parser  # type: ignore

                # JavaScript
                try:
                    import tree_sitter_javascript as tsjs  # type: ignore

                    js_lang = Language(tsjs.language())
                    self._ts_parsers["javascript"] = Parser(js_lang)
                    logger.debug("tree-sitter JavaScript grammar loaded")
                except Exception as e:
                    logger.debug("JS tree-sitter grammar not available: %s", e)

                # Java
                try:
                    import tree_sitter_java as tsjava  # type: ignore

                    java_lang = Language(tsjava.language())
                    self._ts_parsers["java"] = Parser(java_lang)
                    logger.debug("tree-sitter Java grammar loaded")
                except Exception as e:
                    logger.debug("Java tree-sitter grammar not available: %s", e)

            except ImportError:
                logger.debug("tree-sitter Language/Parser not found; tree-sitter features disabled")

        except ImportError:
            logger.debug("tree-sitter not installed; only Python parsing available")

    # ------------------------------------------------------------------
    # Language Detection
    # ------------------------------------------------------------------

    def get_language(self, filepath: str) -> str:
        """Detect the programming language of a file from its extension."""
        ext = Path(filepath).suffix.lower()
        return EXTENSION_LANGUAGE_MAP.get(ext, "unknown")

    # ------------------------------------------------------------------
    # Python Parsing
    # ------------------------------------------------------------------

    def parse_python(self, code: str) -> Dict[str, Any]:
        """
        Parse Python source code using stdlib ``ast``.

        Returns a dict with:
          - ``language``: "python"
          - ``nodes``: list of structured node dicts
          - ``syntax_errors``: list of parse errors (empty on success)
          - ``line_count``: total number of lines
        """
        result: Dict[str, Any] = {
            "language": "python",
            "nodes": [],
            "syntax_errors": [],
            "line_count": code.count("\n") + 1,
            "source": code,
        }

        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            result["syntax_errors"].append(
                {
                    "message": str(exc),
                    "lineno": exc.lineno,
                    "offset": exc.offset,
                    "text": exc.text,
                }
            )
            # Return partial result; rules may still regex-match
            return result

        source_lines = code.splitlines()
        visitor = PythonASTVisitor(source_lines)
        visitor.visit(tree)
        result["nodes"] = visitor.nodes
        return result

    # ------------------------------------------------------------------
    # JavaScript / TypeScript Parsing
    # ------------------------------------------------------------------

    def parse_javascript(self, code: str) -> Dict[str, Any]:
        """
        Parse JavaScript/TypeScript source using tree-sitter.
        Falls back to a minimal regex-based summary if tree-sitter is unavailable.
        """
        result: Dict[str, Any] = {
            "language": "javascript",
            "nodes": [],
            "syntax_errors": [],
            "line_count": code.count("\n") + 1,
            "source": code,
        }

        parser = self._ts_parsers.get("javascript")
        if parser is None:
            logger.debug("JS tree-sitter parser not available; skipping AST walk")
            return result

        try:
            tree = parser.parse(bytes(code, "utf-8"))
            result["nodes"] = self.walk_ast(tree.root_node)
            if tree.root_node.has_error:
                result["syntax_errors"].append({"message": "tree-sitter reported parse errors"})
        except Exception as exc:
            result["syntax_errors"].append({"message": str(exc)})

        return result

    # ------------------------------------------------------------------
    # Java Parsing
    # ------------------------------------------------------------------

    def parse_java(self, code: str) -> Dict[str, Any]:
        """
        Parse Java source code using tree-sitter.
        Falls back gracefully if grammar is unavailable.
        """
        result: Dict[str, Any] = {
            "language": "java",
            "nodes": [],
            "syntax_errors": [],
            "line_count": code.count("\n") + 1,
            "source": code,
        }

        parser = self._ts_parsers.get("java")
        if parser is None:
            logger.debug("Java tree-sitter parser not available; skipping AST walk")
            return result

        try:
            tree = parser.parse(bytes(code, "utf-8"))
            result["nodes"] = self.walk_ast(tree.root_node)
            if tree.root_node.has_error:
                result["syntax_errors"].append({"message": "tree-sitter reported parse errors"})
        except Exception as exc:
            result["syntax_errors"].append({"message": str(exc)})

        return result

    # ------------------------------------------------------------------
    # Generic Tree-sitter AST Walk
    # ------------------------------------------------------------------

    def walk_ast(self, node: Any, depth: int = 0, max_depth: int = 50) -> List[Dict[str, Any]]:
        """
        Recursively walk a tree-sitter node and return a flat list
        of node info dicts.

        Args:
            node: tree-sitter Node object
            depth: current recursion depth (internal)
            max_depth: maximum recursion depth to prevent stack overflow

        Returns:
            List of node info dicts.
        """
        if depth > max_depth:
            return []

        results: List[Dict[str, Any]] = []
        try:
            node_info: Dict[str, Any] = {
                "type": node.type,
                "lineno": node.start_point[0] + 1,
                "col_offset": node.start_point[1],
                "end_lineno": node.end_point[0] + 1,
                "end_col_offset": node.end_point[1],
                "is_named": node.is_named,
            }

            # Capture text for leaf nodes
            if not node.children:
                try:
                    node_info["text"] = node.text.decode("utf-8", errors="replace")
                except Exception:
                    node_info["text"] = ""

            results.append(node_info)

            for child in node.children:
                results.extend(self.walk_ast(child, depth + 1, max_depth))
        except Exception as exc:
            logger.debug("Error walking tree-sitter node: %s", exc)

        return results

    # ------------------------------------------------------------------
    # File-Level Entry Points
    # ------------------------------------------------------------------

    def parse_file(self, filepath: str) -> Dict[str, Any]:
        """
        Read and parse a source file, auto-detecting the language.

        Returns the same structure as the per-language parse methods
        plus a ``filepath`` key.
        """
        language = self.get_language(filepath)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                code = fh.read()
        except OSError as exc:
            logger.error("Cannot read file %s: %s", filepath, exc)
            return {
                "language": language,
                "filepath": filepath,
                "nodes": [],
                "syntax_errors": [{"message": str(exc)}],
                "line_count": 0,
                "source": "",
            }

        result = self.parse_code(code, language)
        result["filepath"] = filepath
        return result

    def parse_code(self, code: str, language: str) -> Dict[str, Any]:
        """
        Parse raw source code for the given language.

        Args:
            code: Source code string.
            language: One of 'python', 'javascript', 'typescript', 'java'.

        Returns:
            Parsed AST dict.
        """
        parsers = {
            "python": self.parse_python,
            "javascript": self.parse_javascript,
            "typescript": self.parse_javascript,  # share JS grammar for TS
            "java": self.parse_java,
        }
        parser_fn = parsers.get(language, self.parse_python)
        return parser_fn(code)
