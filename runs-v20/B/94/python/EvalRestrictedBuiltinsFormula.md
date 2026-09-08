## Verdict

Confirmed. `formula_engine.py` line 4 passes an attacker-influenced `expression` string straight into `eval()`. Stripping `__builtins__` to `{}` (line 4's third argument) is not a sandbox: attribute access, subscripting, and calls remain fully available inside `eval`, so an expression can reach the object graph without ever naming a builtin - e.g. `().__class__.__bases__[0].__subclasses__()` walks from a bare tuple literal to every loaded class, and from there to arbitrary code execution, without referencing `eval`, `import`, or `os` at all.

## Source

`expression` is a parameter to `evaluate_formula(expression, variables)`. The function itself performs no validation and the single file in this call chain shows no caller-side sanitization, so `expression` is treated as fully untrusted, attacker-controlled text - the formula body an end user supplies (e.g. a spreadsheet-style calculation field).

## Fix

### File: formula_engine.py
```python
import ast
import operator

# Node types permitted anywhere in the parsed formula. ast.operator and
# ast.unaryop are the base classes ast.walk() yields for every Add/Sub/...
# and UAdd/USub/... node, so they must be allowlisted alongside the
# concrete node types they attach to (e.g. Name's Load context node).
_ALLOWED_NODES = (
    ast.Expression,
    ast.Constant,
    ast.BinOp,
    ast.UnaryOp,
    ast.Name,
    ast.Load,
    ast.operator,
    ast.unaryop,
)

# ast.Pow is intentionally excluded: an allowed operator with no bound on
# exponent size (e.g. 9 ** 9 ** 9) is a denial-of-service vector.
_ALLOWED_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
}

_ALLOWED_UNARYOPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

_MAX_EXPRESSION_LENGTH = 200


def _eval_node(node, variables):
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, variables)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return node.value
        raise ValueError("Only numeric literals are allowed in a formula")
    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in _ALLOWED_BINOPS:
            raise ValueError(f"Operator '{op_type.__name__}' is not allowed in a formula")
        left = _eval_node(node.left, variables)
        right = _eval_node(node.right, variables)
        return _ALLOWED_BINOPS[op_type](left, right)
    if isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in _ALLOWED_UNARYOPS:
            raise ValueError(f"Operator '{op_type.__name__}' is not allowed in a formula")
        return _ALLOWED_UNARYOPS[op_type](_eval_node(node.operand, variables))
    if isinstance(node, ast.Name):
        if node.id not in variables:
            raise ValueError(f"Unknown variable in formula: {node.id}")
        return variables[node.id]
    raise ValueError(f"Expression contains a disallowed construct: {type(node).__name__}")


def evaluate_formula(expression, variables):
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("Formula expression must be a non-empty string")
    if len(expression) > _MAX_EXPRESSION_LENGTH:
        raise ValueError("Formula expression exceeds the maximum allowed length")

    tree = ast.parse(expression, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise ValueError(f"Expression contains a disallowed construct: {type(node).__name__}")

    context = dict(variables)
    return _eval_node(tree.body, context)
```

## Explanation

The original sink contract: `eval(expression, {"__builtins__": {}}, context)` returns whatever the expression evaluates to, uses `context` (a copy of `variables`) as the local namespace, and raises whatever exception the expression itself raises (`SyntaxError`, `NameError`, `ZeroDivisionError`, `TypeError`, etc.) - none of which the caller is shown to catch. The restricted `__builtins__` dict is the part that looks like a defence but is not one: CPython's own documentation is explicit that overriding `__builtins__` "is *not* a security mechanism: the executed code can still access all builtins" through attribute access and introspection, so `eval` with untrusted input has to be removed rather than contained, per the loaded CWE-94 Python guidance.

The fix replaces the evaluator entirely, following that guidance's AST-allowlist pattern for the case where an expression must be evaluated: `ast.parse(expression, mode="eval")` builds a tree, `ast.walk` checks every node against an allowlist of `Expression`, `Constant`, `BinOp`, `UnaryOp`, `Name`, `Load`, and the `operator`/`unaryop` base classes, and a second pass (`_eval_node`) interprets only that same closed set of node types itself, dispatching to Python's own `operator` functions rather than back through `eval`/`compile`. There is no `Call`, `Attribute`, or `Subscript` node in the allowlist, so the object-graph pivot (`().__class__.__bases__[0]...`) and any function call are structurally unreachable, not merely denylisted - closing the exact gap the stripped-builtins approach left open. `Name` lookups are resolved against `variables`, the set the caller actually supplies (never `globals()`), matching the guidance's requirement to scope variable access to caller-supplied names. `ast.Pow` is left out of the operator dispatch table (while still passing the `ast.operator` walk-level check, since Python has no separate `Pow` node-vs-base-class distinction) so it fails at evaluation time with a clear `ValueError`, closing the unbounded-exponent DoS the guidance calls out. An expression length cap (`_MAX_EXPRESSION_LENGTH = 200`) is added as defense-in-depth against oversized input, consistent with the guidance's instruction to cap input size before evaluation.

Checks performed: `python -m py_compile` on the fixed file in an isolated scratch copy succeeded. It was then imported and exercised directly: legitimate formulas (`price * qty + 1`, `-price / qty`) still compute the expected numeric result; the known `eval`-with-empty-`__builtins__` bypass (`().__class__.__bases__[0].__subclasses__()`) and a hypothetical `__import__("os").system(...)` payload both raise `ValueError` for a disallowed `Call` node; `9 ** 9 ** 9` raises `ValueError` for the disallowed `Pow` operator; and a reference to a name not in `variables` raises `ValueError` instead of silently resolving. Every name used (`ast.Expression`, `ast.Constant`, `ast.BinOp`, `ast.UnaryOp`, `ast.Name`, `ast.Load`, `ast.operator`, `ast.unaryop`, `ast.parse`, `ast.walk`, `operator.add/sub/mul/truediv/mod/pos/neg`) is from the Python standard library `ast` and `operator` modules named directly in the loaded guidance or documented in the standard library.

## Behaviour changes

- `evaluate_formula` now supports only numeric literals, variable references present in the `variables` argument, and the binary operators `+ - * / %` plus unary `+`/`-`. String, boolean, `None`, list/tuple/dict literals, comparisons, boolean logic, attribute access, subscripting, and function calls are no longer evaluable - any expression using them now raises `ValueError` instead of the value it previously produced (for string/other-typed constants) or the arbitrary behaviour it previously permitted (for calls/attribute access).
- `**` (exponentiation) is no longer supported; it now raises `ValueError` instead of computing a result. Formulas that legitimately relied on `**` will need to be rewritten (e.g. repeated multiplication) or the caller will need to handle the new error.
- Referencing a variable name not present in the supplied `variables` dict now raises `ValueError` with an explicit "Unknown variable" message, where previously it raised `NameError` (since the restricted-but-not-empty builtins were still technically reachable via introspection, a name miss would ordinarily surface as `NameError` from `eval`).
- Expressions longer than 200 characters now raise `ValueError` immediately, a new constraint that did not exist before (`eval` had no length limit).
- All rejection paths raise `ValueError` with a descriptive message, whereas the previous code could raise `SyntaxError`, `NameError`, `TypeError`, `ZeroDivisionError`, or (via the sandbox-escape path) execute arbitrary code with no exception at all. Callers that pattern-matched on specific exception types from `eval` will need to catch `ValueError` instead; `ZeroDivisionError` from `/` and `%` by zero is preserved unchanged since those still go through Python's native `operator.truediv`/`operator.mod`.
