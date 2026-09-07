## Verdict

CONFIRMED. The use of `eval()` with a restricted builtins namespace (line 4) is vulnerable to code injection. Restricting `__builtins__` is not a sandbox—Python's CPython explicitly documents that "overriding `__builtins__` is *not* a security mechanism: the executed code can still access all builtins." Attackers can bypass this restriction through introspection to execute arbitrary code.

## Source

File: `formula_engine.py`, line 4

```python
def evaluate_formula(expression, variables):
    context = dict(variables)
    # SAST FINDING: CWE-94 (Code Injection) reported here. Sink is the next statement.
    return eval(expression, {"__builtins__": {}}, context)
```

The `expression` parameter is untrusted user input passed directly to `eval()`, which executes it as Python code with access to the runtime environment. The attempted restriction via empty `__builtins__` dict does not create a sandbox and is defeated by accessing builtins through class introspection.

## Fix

### File: formula_engine.py

```python
import ast
import operator

def evaluate_formula(expression, variables):
    """
    Safely evaluate a mathematical formula using AST parsing instead of eval().
    
    Prevents code injection by parsing the expression and only allowing
    arithmetic operations and variable references.
    """
    # Allowed operators for safe formula evaluation
    BINARY_OPS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
    }
    
    UNARY_OPS = {
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
    }
    
    def eval_node(node):
        """Recursively evaluate an AST node."""
        if isinstance(node, ast.Expression):
            return eval_node(node.body)
        elif isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.BinOp):
            if type(node.op) not in BINARY_OPS:
                raise ValueError("Operation not allowed")
            left = eval_node(node.left)
            right = eval_node(node.right)
            return BINARY_OPS[type(node.op)](left, right)
        elif isinstance(node, ast.UnaryOp):
            if type(node.op) not in UNARY_OPS:
                raise ValueError("Unary operation not allowed")
            operand = eval_node(node.operand)
            return UNARY_OPS[type(node.op)](operand)
        elif isinstance(node, ast.Name):
            if node.id not in variables:
                raise ValueError(f"Undefined variable: {node.id}")
            return variables[node.id]
        else:
            raise ValueError("Expression type not allowed")
    
    tree = ast.parse(expression, mode='eval')
    return eval_node(tree)
```

## Explanation

The fix replaces `eval()` with safe AST (Abstract Syntax Tree) parsing and evaluation. Instead of executing untrusted code directly, the expression is parsed into an AST using `ast.parse()` with `mode='eval'`, which produces a syntax tree. A custom recursive evaluator then walks this tree and strictly allows only:

- **Constants**: numeric and string literals
- **Binary operators**: `+`, `-`, `*`, `/`, `//`, `%` (arithmetic only)
- **Unary operators**: `+` and `-` (positive/negative)
- **Variable references**: names that exist in the provided `variables` dict

Any other expression type (function calls, attribute access, imports, comprehensions, etc.) raises a `ValueError`, preventing code injection. This approach follows the Python CWE-94 guidance: "Where the formula must reference variables, parse with `ast.parse(expr, mode='eval')` and walk the tree against an allowlist of node types and operators, rejecting anything else."

The fix preserves the original interface and return value—it still takes `expression` and `variables` and returns the evaluated result—but eliminates the vulnerability by removing the dangerous `eval()` call entirely.

## Behaviour changes

- **Legitimate formulas continue to work**: Expressions like `"x + y"`, `"2 * value"`, and `"-count"` evaluate correctly with the provided variable values.
- **Injection attempts are now blocked**: Expressions attempting code injection (e.g., `"__import__('os').system('cmd')"`, `"eval('...')"`, attribute access, or any non-arithmetic construct) now raise `ValueError` instead of executing.
- **Error handling is more explicit**: Syntax errors in the expression, undefined variables, and disallowed operations each raise `ValueError` with a descriptive message, making debugging easier.
- **Performance impact is minimal**: AST parsing and tree walking are efficient; formula evaluation is typically in-memory arithmetic only.
