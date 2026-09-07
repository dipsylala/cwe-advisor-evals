## Verdict

Confirmed. The `eval()` call on line 4 accepts untrusted `expression` input directly. The attempted mitigation via `{"__builtins__": {}}` is not a sandbox — CPython documentation explicitly states this is "not a security mechanism: the executed code can still access all builtins". This is CWE-94 Code Injection.

## Source

**File:** `evals/cases/94/python/EvalRestrictedBuiltinsFormula/formula_engine.py:4`

**Function:** `evaluate_formula(expression, variables)`

**Data flow:**
- Source: `expression` parameter (untrusted user input)
- Sink: `eval(expression, {"__builtins__": {}}, context)` on line 4
- The globals namespace restriction does not prevent access to builtins or other dangerous operations through introspection and object references

## Fix

Replace the `eval()` sink with safe AST parsing and validation:

```python
import ast
import operator


def evaluate_formula(expression, variables):
    """Safely evaluate a mathematical formula with restricted operations."""
    # Define safe binary operations
    SAFE_BIN_OPS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
    }
    
    # Define safe unary operations
    SAFE_UNARY_OPS = {
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
    }
    
    try:
        # Parse expression into AST
        tree = ast.parse(expression, mode='eval')
    except SyntaxError as e:
        raise ValueError(f"Invalid formula syntax: {e}")
    
    # Validate and evaluate the AST
    def safe_eval(node):
        if isinstance(node, ast.Expression):
            return safe_eval(node.body)
        elif isinstance(node, ast.Constant):
            # Allow only numeric constants
            if not isinstance(node.value, (int, float, complex)):
                raise ValueError("Non-numeric constants not allowed")
            return node.value
        elif isinstance(node, ast.BinOp):
            if type(node.op) not in SAFE_BIN_OPS:
                raise ValueError(f"Binary operation not allowed: {type(node.op).__name__}")
            left = safe_eval(node.left)
            right = safe_eval(node.right)
            return SAFE_BIN_OPS[type(node.op)](left, right)
        elif isinstance(node, ast.UnaryOp):
            if type(node.op) not in SAFE_UNARY_OPS:
                raise ValueError(f"Unary operation not allowed: {type(node.op).__name__}")
            operand = safe_eval(node.operand)
            return SAFE_UNARY_OPS[type(node.op)](operand)
        elif isinstance(node, ast.Name):
            if node.id not in variables:
                raise ValueError(f"Undefined variable: {node.id}")
            return variables[node.id]
        else:
            raise ValueError(f"Expression type not allowed: {type(node).__name__}")
    
    try:
        return safe_eval(tree)
    except (ValueError, ZeroDivisionError, OverflowError, TypeError) as e:
        raise ValueError(f"Formula evaluation failed: {e}")
```

## Explanation

The fix replaces `eval()` with a safe evaluator that:

1. **Parses without executing:** Uses `ast.parse(expression, mode='eval')` to parse the expression into an Abstract Syntax Tree without executing any code.

2. **Validates node types:** The `safe_eval()` recursive function validates every node in the AST and rejects any type that is not in the allowlist (Expression, Constant, BinOp, UnaryOp, Name).

3. **Restricts operations:** Only arithmetic operators (`+`, `-`, `*`, `/`, `//`, `%`, `**`) and unary operators (`+`, `-`) are allowed. This prevents attribute access, function calls, imports, comprehensions, and all other code execution paths.

4. **Controls variable access:** The `ast.Name` handler checks that each variable name is defined in the caller-supplied `variables` dictionary, preventing access to globals, builtins, or undefined names.

5. **Avoids eval() entirely:** The fix never uses `eval()`, `exec()`, `compile()`, or any dynamic code execution function. No namespace restriction is needed because the code is never executed by Python's evaluator—it is evaluated by a controlled walker that only performs arithmetic.

This eliminates the injection vector: even if an attacker crafts a malicious expression, they cannot execute arbitrary code, import modules, access object internals, or read environment variables.

## Behaviour changes

**Backward-compatible for valid formulas:**
- Expressions using only arithmetic operators and defined variables continue to work and return the same result.
- Example: `evaluate_formula("price * qty + tax", {"price": 10, "qty": 5, "tax": 2})` still returns `52`.

**Rejects formerly-working injection attacks:**
- Expressions with attribute access, function calls, imports, or list comprehensions now raise `ValueError` instead of executing code.
- Example: `evaluate_formula("__import__('os').system('...')", {})` raises `ValueError: Expression type not allowed: Call`.

**Error handling:**
- Syntax errors are caught and raised as `ValueError` with a descriptive message.
- Invalid variable references raise `ValueError: Undefined variable: ...`.
- Forbidden operations raise `ValueError: ... not allowed: ...`.
- Arithmetic errors (division by zero, overflow) are caught and wrapped in `ValueError`.
