## Verdict
exploitable

## Source
The `expression` parameter passed to `evaluate_formula()` is untrusted and attacker-controlled, passed directly to `eval()` without restriction.

## Fix

**Vulnerable code:**
```python
def evaluate_formula(expression, variables):
    context = dict(variables)
    # SAST FINDING: CWE-94 (Code Injection) reported here. Sink is the next statement.
    return eval(expression, {"__builtins__": {}}, context)
```

**Fixed code:**
```python
import ast
import operator

def evaluate_formula(expression, variables):
    """Safely evaluate a mathematical expression using AST-based parsing."""
    # Define allowed operations for mathematical formulas
    OPERATORS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
    }
    
    # Parse the expression into an AST
    try:
        tree = ast.parse(expression, mode='eval')
    except SyntaxError as e:
        raise ValueError(f"Invalid expression: {e}")
    
    def evaluate_node(node):
        """Recursively evaluate an AST node against the allowlist."""
        if isinstance(node, ast.Expression):
            return evaluate_node(node.body)
        elif isinstance(node, ast.Constant):
            # Allow numeric and string literals
            return node.value
        elif isinstance(node, ast.Name):
            # Allow only variables provided in the context
            if node.id not in variables:
                raise ValueError(f"Undefined variable: {node.id}")
            return variables[node.id]
        elif isinstance(node, ast.BinOp):
            # Allow binary operations (+, -, *, /, etc.)
            left = evaluate_node(node.left)
            right = evaluate_node(node.right)
            op = OPERATORS.get(type(node.op))
            if op is None:
                raise ValueError(f"Operation not allowed: {type(node.op).__name__}")
            return op(left, right)
        elif isinstance(node, ast.UnaryOp):
            # Allow unary operations (+, -)
            operand = evaluate_node(node.operand)
            op = OPERATORS.get(type(node.op))
            if op is None:
                raise ValueError(f"Operation not allowed: {type(node.op).__name__}")
            return op(operand)
        else:
            # Reject all other node types (function calls, attribute access, etc.)
            raise ValueError(f"Expression type not allowed: {type(node).__name__}")
    
    try:
        return evaluate_node(tree)
    except (ValueError, TypeError, ZeroDivisionError) as e:
        raise ValueError(f"Error evaluating expression: {e}")
```

## Explanation

The vulnerability arises from using `eval()` to execute untrusted input as Python code. Even with a restricted `__builtins__` dictionary, CPython's documentation explicitly states this is not a security mechanism—attackers can use reflection, introspection, and attribute lookup to access restricted functionality. The fix replaces `eval()` with safe AST-based parsing and recursive evaluation. The expression is parsed into an Abstract Syntax Tree, then each node is validated against an allowlist of safe types: `ast.Expression`, `ast.Constant` (literals), `ast.Name` (variables from the provided dict), `ast.BinOp` (binary operators), and `ast.UnaryOp` (unary operators). Function calls, attribute access, subscripts, and other dangerous operations are rejected, eliminating code injection while preserving the ability to evaluate mathematical formulas safely.

## Behaviour changes

The fixed code raises `ValueError` with descriptive messages for invalid or disallowed expressions (e.g., undefined variables, unsafe operations, syntax errors), whereas the original `eval()` would raise exceptions like `NameError`, `SyntaxError`, or `AttributeError` directly. The specific exception type and message differ, but both fail safely when given invalid input. The return value and successful evaluation paths are identical to the original when given valid mathematical expressions using only permitted operations and variables from the context dict.
