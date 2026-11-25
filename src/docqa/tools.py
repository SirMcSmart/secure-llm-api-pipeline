"""The one tool the model may call: arithmetic. Parsed with `ast` against an allow-list of node
types, so model output is treated as data and never executed (OWASP LLM05/LLM06, CWE-95)."""

from __future__ import annotations

import ast
import operator

_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
}
_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}
MAX_EXPR_CHARS = 100
MAX_ABS_VALUE = 1e12


class UnsafeExpression(ValueError):
    pass


def safe_calc(expr: str) -> float:
    if len(expr) > MAX_EXPR_CHARS:
        raise UnsafeExpression("expression too long")
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise UnsafeExpression("not an arithmetic expression") from exc
    return _eval(tree.body)


def _eval(node: ast.AST) -> float:
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        value = float(node.value)
    elif isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
        value = _BINOPS[type(node.op)](_eval(node.left), _eval(node.right))
    elif isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
        value = _UNARY[type(node.op)](_eval(node.operand))
    else:
        # No names, calls, attributes, subscripts, comprehensions or exponentiation (CPU DoS).
        raise UnsafeExpression(f"disallowed syntax: {type(node).__name__}")
    if abs(value) > MAX_ABS_VALUE:
        raise UnsafeExpression("value out of range")
    return value
