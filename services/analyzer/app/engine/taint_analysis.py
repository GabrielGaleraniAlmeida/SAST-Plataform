"""Bounded, same-file Python source-to-sink analysis using the standard AST."""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Set, Tuple


def _dotted(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


@dataclass(frozen=True)
class _Taint:
    source: str
    source_line: int
    variable: str
    chain: Tuple[str, ...]
    sanitizers: Tuple[str, ...] = ()


Environment = Dict[str, List[_Taint]]


class TaintAnalyzer:
    """Track selected Python taint flows within a function or same-file call chain.

    This is a bounded AST approximation, not a control-flow, type, or whole-program
    analysis. It resolves module-level simple-name calls only, analyzes one pass
    through branches and loops, and does not resolve attributes, imports, reflection,
    or cross-file calls.
    """

    SOURCES: Set[str] = {
        "request.args",
        "request.form",
        "request.json",
        "request.cookies",
        "request.headers",
        "request.data",
        "request.values",
        "sys.argv",
        "os.environ",
    }

    CALL_SOURCES: Set[str] = {
        "request.get_json",
        "input",
        "os.getenv",
    }

    SINKS: Set[str] = {
        "os.system",
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
        "render_template",
        "render_template_string",
    }
    METHOD_SINKS: Set[str] = {
        "execute", "run", "Popen", "call", "check_call", "check_output"
    }

    SANITIZER_SINKS: Dict[str, Set[str]] = {
        "shlex.quote": {"os.system", "run", "Popen", "call", "check_call", "check_output"},
        "html.escape": {"render_template", "render_template_string"},
        "markupsafe.escape": {"render_template", "render_template_string"},
        "bleach.clean": {"render_template", "render_template_string"},
    }

    MAX_CALL_DEPTH = 4

    def analyze(self, ast_data: dict, source_code: str) -> List[Dict[str, Any]]:
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        self._functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        function_definitions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self._flows: List[Dict[str, Any]] = []
        self._flow_keys: Set[Tuple[Any, ...]] = set()

        self._execute_block(
            [node for node in tree.body if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))],
            {},
            [],
            0,
            set(),
        )
        for function in function_definitions:
            self._execute_block(function.body, {}, [function.name], 0, {function.name})

        return self._flows

    def _execute_block(
        self,
        statements: List[ast.stmt],
        env: Environment,
        scope: List[str],
        depth: int,
        active_calls: Set[str],
    ) -> List[_Taint]:
        returned: List[_Taint] = []

        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue

            if isinstance(statement, ast.Assign):
                taints = self._eval_expr(statement.value, env, scope, depth, active_calls)
                for target in statement.targets:
                    self._assign_target(target, taints, env)
            elif isinstance(statement, ast.AnnAssign):
                taints = self._eval_expr(statement.value, env, scope, depth, active_calls) if statement.value else []
                self._assign_target(statement.target, taints, env)
            elif isinstance(statement, ast.AugAssign):
                current = self._eval_expr(statement.target, env, scope, depth, active_calls)
                added = self._eval_expr(statement.value, env, scope, depth, active_calls)
                self._assign_target(statement.target, self._merge_taints(current, added), env)
            elif isinstance(statement, ast.Expr):
                self._eval_expr(statement.value, env, scope, depth, active_calls)
            elif isinstance(statement, ast.Return):
                if statement.value:
                    returned.extend(self._eval_expr(statement.value, env, scope, depth, active_calls))
                break
            elif isinstance(statement, ast.If):
                self._eval_expr(statement.test, env, scope, depth, active_calls)
                left = {name: list(items) for name, items in env.items()}
                right = {name: list(items) for name, items in env.items()}
                left_returns = self._execute_block(statement.body, left, scope, depth, active_calls)
                right_returns = self._execute_block(statement.orelse, right, scope, depth, active_calls)
                env.clear()
                env.update(self._merge_environments(left, right))
                returned.extend(self._merge_taints(left_returns, right_returns))
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                if isinstance(statement, (ast.For, ast.AsyncFor)):
                    iterable_taint = self._eval_expr(statement.iter, env, scope, depth, active_calls)
                    self._assign_target(statement.target, iterable_taint, env)
                else:
                    self._eval_expr(statement.test, env, scope, depth, active_calls)
                body = {name: list(items) for name, items in env.items()}
                body_returns = self._execute_block(statement.body, body, scope, depth, active_calls)
                otherwise = {name: list(items) for name, items in env.items()}
                else_returns = self._execute_block(statement.orelse, otherwise, scope, depth, active_calls)
                env.clear()
                env.update(self._merge_environments(body, otherwise))
                returned.extend(self._merge_taints(body_returns, else_returns))
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    value_taint = self._eval_expr(item.context_expr, env, scope, depth, active_calls)
                    if item.optional_vars:
                        self._assign_target(item.optional_vars, value_taint, env)
                returned.extend(self._execute_block(statement.body, env, scope, depth, active_calls))
            elif isinstance(statement, ast.Try):
                paths = [statement.body, *[handler.body for handler in statement.handlers]]
                branch_envs = []
                for path in paths:
                    branch = {name: list(items) for name, items in env.items()}
                    returned.extend(self._execute_block(path, branch, scope, depth, active_calls))
                    branch_envs.append(branch)
                if statement.orelse:
                    branch = {name: list(items) for name, items in env.items()}
                    returned.extend(self._execute_block(statement.orelse, branch, scope, depth, active_calls))
                    branch_envs.append(branch)
                merged = branch_envs[0] if branch_envs else env
                for branch in branch_envs[1:]:
                    merged = self._merge_environments(merged, branch)
                env.clear()
                env.update(merged)
                returned.extend(self._execute_block(statement.finalbody, env, scope, depth, active_calls))
            else:
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.expr):
                        self._eval_expr(child, env, scope, depth, active_calls)

        return self._dedupe_taints(returned)

    def _eval_expr(
        self,
        expr: Optional[ast.AST],
        env: Environment,
        scope: List[str],
        depth: int,
        active_calls: Set[str],
    ) -> List[_Taint]:
        if expr is None:
            return []
        source = self._source_label(expr)
        if source:
            line = getattr(expr, "lineno", 1)
            return [_Taint(source, line, source, (source,))]

        if isinstance(expr, ast.Name):
            return list(env.get(expr.id, []))
        if isinstance(expr, ast.Subscript):
            return self._eval_expr(expr.value, env, scope, depth, active_calls)
        if isinstance(expr, ast.Call):
            name = _dotted(expr.func) or ""
            args = [
                taint
                for argument in [*expr.args, *(keyword.value for keyword in expr.keywords)]
                for taint in self._eval_expr(argument, env, scope, depth, active_calls)
            ]
            if name not in self._functions and self._is_sink(name, expr.func):
                self._record_sink(expr, name, args, scope)

            if name in self.SANITIZER_SINKS:
                return [
                    replace(taint, sanitizers=taint.sanitizers + (name,))
                    for taint in self._dedupe_taints(args)
                ]

            if isinstance(expr.func, ast.Attribute) and expr.func.attr in {
                "append", "extend", "add", "insert", "update", "setdefault"
            }:
                self._record_mutation(expr.func.value, args, env)

            function_name = name if isinstance(expr.func, ast.Name) else None
            function = self._functions.get(function_name or "")
            if (
                function is not None
                and function_name not in active_calls
                and depth < self.MAX_CALL_DEPTH
            ):
                call_env = self._bind_arguments(function, expr, env, scope, depth, active_calls)
                returned = self._execute_block(
                    function.body,
                    call_env,
                    [*scope, function.name],
                    depth + 1,
                    active_calls | {function.name},
                )
                return [
                    replace(taint, chain=taint.chain + (function.name,))
                    for taint in self._dedupe_taints(returned)
                ]
            return self._dedupe_taints(args)

        if isinstance(expr, ast.Attribute):
            return self._eval_expr(expr.value, env, scope, depth, active_calls)

        child_taints: List[_Taint] = []
        for child in ast.iter_child_nodes(expr):
            if isinstance(child, ast.expr):
                child_taints.extend(self._eval_expr(child, env, scope, depth, active_calls))
        return self._dedupe_taints(child_taints)

    def _bind_arguments(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        call: ast.Call,
        caller_env: Environment,
        scope: List[str],
        depth: int,
        active_calls: Set[str],
    ) -> Environment:
        params = [*function.args.posonlyargs, *function.args.args]
        bound: Environment = {}
        for parameter, argument in zip(params, call.args):
            bound[parameter.arg] = [
                replace(taint, variable=parameter.arg, chain=taint.chain + (parameter.arg,))
                for taint in self._eval_expr(argument, caller_env, scope, depth, active_calls)
            ]
        param_names = {parameter.arg for parameter in [*params, *function.args.kwonlyargs]}
        for keyword in call.keywords:
            if keyword.arg in param_names:
                bound[keyword.arg] = self._eval_expr(
                    keyword.value, caller_env, scope, depth, active_calls
                )
                bound[keyword.arg] = [
                    replace(taint, variable=keyword.arg, chain=taint.chain + (keyword.arg,))
                    for taint in bound[keyword.arg]
                ]
        return bound

    def _assign_target(self, target: ast.AST, taints: List[_Taint], env: Environment) -> None:
        if isinstance(target, ast.Name):
            if taints:
                env[target.id] = [
                    replace(taint, variable=target.id, chain=taint.chain + (target.id,))
                    for taint in self._dedupe_taints(taints)
                ]
            else:
                env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign_target(element, taints, env)
        elif isinstance(target, ast.Subscript):
            self._record_mutation(target.value, taints, env)

    @staticmethod
    def _record_mutation(target: ast.AST, taints: List[_Taint], env: Environment) -> None:
        if isinstance(target, ast.Name) and taints:
            env[target.id] = TaintAnalyzer._dedupe_taints(
                [*env.get(target.id, []), *taints]
            )

    def _record_sink(
        self, call: ast.Call, sink: str, taints: List[_Taint], scope: List[str]
    ) -> None:
        for taint in self._dedupe_taints(taints):
            sink_name = sink.split(".")[-1]
            sanitized = any(
                sink in self.SANITIZER_SINKS.get(sanitizer, set())
                or sink_name in self.SANITIZER_SINKS.get(sanitizer, set())
                for sanitizer in taint.sanitizers
            )
            flow = {
                "source": taint.source,
                "sink": sink,
                "source_line": taint.source_line,
                "sink_line": call.lineno,
                "path": [taint.source_line, call.lineno],
                "is_sanitized": sanitized,
                "variable": taint.variable,
                "function_name": scope[-1] if scope else None,
                "intermediates": list(dict.fromkeys(taint.chain)),
            }
            key = (
                flow["source"], flow["sink"], flow["source_line"], flow["sink_line"],
                flow["variable"], flow["function_name"], tuple(flow["intermediates"]),
            )
            if key not in self._flow_keys:
                self._flow_keys.add(key)
                self._flows.append(flow)

    def _source_label(self, node: ast.AST) -> Optional[str]:
        name = _dotted(node)
        if name in self.SOURCES:
            return name
        if isinstance(node, ast.Subscript):
            base = _dotted(node.value)
            if base in self.SOURCES:
                return base
        if isinstance(node, ast.Call):
            func_name = _dotted(node.func)
            if func_name in self.CALL_SOURCES:
                return func_name
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                base = _dotted(node.func.value)
                if base in self.SOURCES:
                    return base
        return None

    def _is_sink(self, name: str, function: ast.AST) -> bool:
        if name in self.SINKS:
            return True
        if isinstance(function, ast.Name):
            return name in {"eval", "exec", "compile", "__import__"}
        return isinstance(function, ast.Attribute) and (
            function.attr in self.SINKS or function.attr in self.METHOD_SINKS
        )

    @staticmethod
    def _merge_taints(*groups: List[_Taint]) -> List[_Taint]:
        return TaintAnalyzer._dedupe_taints([taint for group in groups for taint in group])

    @staticmethod
    def _dedupe_taints(taints: List[_Taint]) -> List[_Taint]:
        return list(dict.fromkeys(taints))

    @staticmethod
    def _merge_environments(*environments: Environment) -> Environment:
        merged: Environment = {}
        for env in environments:
            for name, taints in env.items():
                merged[name] = TaintAnalyzer._merge_taints(merged.get(name, []), taints)
        return merged
