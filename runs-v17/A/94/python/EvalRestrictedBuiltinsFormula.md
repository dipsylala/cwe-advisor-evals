## Verdict
CONFIRMED. The code uses `eval()` to execute user-supplied expressions, which is unsafe even with restricted `__builtins__`. Attackers can bypass restrictions through object attribute access, comprehensions, and gadget chains.

## Source
File: formula_engine.py, line 4
```python
return eval(expression, {"__builtins__": {}}, context)
```

The vulnerability occurs because `eval()` executes arbitrary Python code. Restricting `__builtins__` to an empty dict does not prevent:
- Access to object attributes via `.__class__`, `.__bases__`, etc.
- List/dict/set comprehensions
- Lambda functions and nested operations
- Attribute-based gadget chains for code execution

## Fix

### File: formula_engine.py

```python
import ast
import operator

def evaluate_formula(expression, variables):
    # SAST FINDING: CWE-94 (Code Injection) remediated by replacing eval() with safe AST-based evaluation.
    return _safe_eval(expression, variables)

def _safe_eval(expr_string, variables):
    """Safely evaluate a mathematical/formula expression using AST parsing.
    
    Only allows:
    - Numeric and string literals
    - Variable references from the provided context
    - Safe binary operators (+, -, *, /, //, %, **)
    - Safe unary operators (+, -)
    - Parenthesized sub-expressions
    
    Raises ValueError for any disallowed node types or operations.
    """
    try:
        tree = ast.parse(expr_string, mode='eval')
    except SyntaxError as e:
        raise ValueError(f"Invalid expression: {e}")
    
    return _eval_node(tree.body, variables)

def _eval_node(node, variables):
    """Recursively evaluate an AST node."""
    # Allow numeric and string literals
    if isinstance(node, ast.Constant):
        return node.value
    
    # Python 3.7 compatibility: also check Num, Str, NameConstant
    if isinstance(node, ast.Num):
        return node.n
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.NameConstant):
        return node.value
    
    # Allow variable lookup (safe if variables dict is trusted)
    if isinstance(node, ast.Name):
        if node.id in variables:
            return variables[node.id]
        raise ValueError(f"Undefined variable: {node.id}")
    
    # Allow binary operations with safe operators
    if isinstance(node, ast.BinOp):
        left = _eval_node(node.left, variables)
        right = _eval_node(node.right, variables)
        op_map = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.FloorDiv: operator.floordiv,
            ast.Mod: operator.mod,
            ast.Pow: operator.pow,
        }
        if type(node.op) not in op_map:
            raise ValueError(f"Disallowed operator: {type(node.op).__name__}")
        return op_map[type(node.op)](left, right)
    
    # Allow unary operations
    if isinstance(node, ast.UnaryOp):
        operand = _eval_node(node.operand, variables)
        if isinstance(node.op, ast.UAdd):
            return +operand
        elif isinstance(node.op, ast.USub):
            return -operand
        else:
            raise ValueError(f"Disallowed unary operator: {type(node.op).__name__}")
    
    # Reject all other node types (calls, attributes, comprehensions, etc.)
    raise ValueError(f"Expression type not allowed: {type(node).__name__}")
```

## Explanation

**Why `eval()` with empty `__builtins__` is still dangerous:**

The original code attempted to restrict `eval()` by providing an empty `__builtins__` dictionary. However, this does not prevent code injection because:

1. Attackers can access object attributes and methods through the `.__class__` and `.__bases__` chain to access unrestricted built-ins
2. List comprehensions, set comprehensions, and generator expressions are language constructs that bypass the builtins restriction
3. Lambda functions and nested expressions can be used to execute arbitrary code
4. The mechanism relies on blacklisting (what's forbidden) rather than whitelisting (what's allowed)

**Why the fix is safe:**

The fixed implementation uses `ast.parse()` to convert the expression string into an Abstract Syntax Tree, then walks the tree to evaluate only whitelisted node types:

- **Literals** (numbers, strings): safe to evaluate
- **Variables**: resolved from a trusted context dictionary
- **Binary operators** (+, -, *, /, //, %, **): restricted to mathematical operations
- **Unary operators** (+, -): safe for formula evaluation
- **Rejects everything else**: attribute access, function calls, comprehensions, subscripts, etc.

This approach inverts the security model from "allow everything except builtins" to "allow only specific safe operations," which is a more secure defense-in-depth strategy for formula evaluation.
