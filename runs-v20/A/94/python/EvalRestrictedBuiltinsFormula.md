## Verdict

Confirmed. `evaluate_formula` passes an attacker-influenced `expression` string straight into `eval()`. Stripping `__builtins__` down to `{}` blocks direct calls to `open`, `__import__`, etc., but it does not remove access to Python's live object graph: any expression can still reach `object` through ordinary attribute and subscript syntax (for example `().__class__.__bases__[0].__subclasses__()`), walk the subclass list to find a class such as a subprocess wrapper or file object, and use it to run arbitrary code or read/write arbitrary files. The restricted-builtins pattern is a well-known, publicly documented bypass, not a defense.

## Source

`expression` is the untrusted input; it flows unmodified into the `eval()` call on the line flagged by the scanner:

```
E:/Github/cwe-advisor/evals/cases/94/python/EvalRestrictedBuiltinsFormula/formula_engine.py:4
    return eval(expression, {"__builtins__": {}}, context)
```

`variables` is attacker-influenced too (it becomes part of `context`, the `eval` locals), but the actual code-injection sink is `expression` being interpreted as arbitrary Python syntax rather than as a formula.

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

The fix removes `eval()` entirely rather than trying to further sandbox it - `__builtins__` stripping is exactly the kind of denylist-style sandbox that has repeated public bypasses, so no amount of tightening it closes the class of attack.

Instead, `expression` is parsed with `ast.parse(..., mode="eval")` into a syntax tree, and a bounded interpreter (`_eval_node`) walks that tree itself, evaluating only the handful of node types a numeric formula needs: literal numbers, named variables drawn from the caller-supplied `variables` mapping, and the arithmetic binary/unary operators. Before interpretation, `ast.walk()` performs a second, independent pass that rejects the whole expression if any node anywhere in the tree is not on the allowlist - this catches constructs that could otherwise hide inside a nested position (a lambda body, a comprehension element, a call argument) that the recursive evaluator might not otherwise visit.

Critically, there is no `Call`, `Attribute`, or `Subscript` node in `_ALLOWED_NODES`. That is what actually closes the vulnerability: `().__class__` requires `Attribute`, `[0]` requires `Subscript`, and `__subclasses__()` requires `Call` - all three are rejected before any evaluation happens, so the object-graph walk that defeats `{"__builtins__": {}}` has no syntax left to express it in. Because the interpreter never calls `eval`/`exec` and only produces `int`/`float` values, there is no reachable path back to `object`, and therefore no way to reach `subprocess`, `os`, or the filesystem, regardless of what the caller passes as `expression`.

`ast.Pow` is deliberately left off the allowed binary operators - unlike a bypass, an unbounded exponent (e.g. a huge power) is a CPU/memory exhaustion risk. A hard cap on expression length (`_MAX_EXPRESSION_LENGTH`) adds a second, cheap denial-of-service guard against pathologically long inputs before parsing even begins.

Any expression using disallowed syntax (attribute access, subscripting, calls, comprehensions, lambdas, `**`, boolean literals passed as numbers, etc.) now raises `ValueError` with a message identifying the offending construct, and any variable name not present in the caller's `variables` mapping is also rejected, preserving the original function's behavior of failing on unknown names instead of silently resolving them from an outer scope.
