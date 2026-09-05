## Verdict

Exploitable. The `eval()` function is called with user-controlled input (`expression` parameter). Python's CPython documentation explicitly states that overriding `__builtins__` "is *not* a security mechanism: the executed code can still access all builtins" through introspection and attribute access, allowing arbitrary code execution.

## Source

The `expression` parameter passed to `evaluate_formula()` is untrusted user input that flows directly to the code injection sink.

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

def evaluate_formula(expression, variables):
    # Enforce input length limit to prevent DoS
    if len(expression) > 1000:
        raise ValueError("Expression too long")
    
    # Parse the expression into an AST
    try:
        tree = ast.parse(expression, mode='eval')
    except SyntaxError as e:
        raise ValueError(f"Invalid expression: {e}")
    
    # Validate the AST against an allowlist of safe nodes
    _validate_formula_ast(tree.body, set(variables.keys()))
    
    # Safely evaluate the validated expression
    return _evaluate_formula_ast(tree.body, variables)


def _validate_formula_ast(node, allowed_names):
    """Validate AST contains only safe nodes for formula evaluation."""
    if isinstance(node, ast.Constant):
        return
    elif isinstance(node, ast.Name):
        if node.id not in allowed_names:
            raise ValueError(f"Undefined variable: {node.id}")
    elif isinstance(node, ast.BinOp):
        if not isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow)):
            raise ValueError(f"Unsupported operator: {type(node.op).__name__}")
        _validate_formula_ast(node.left, allowed_names)
        _validate_formula_ast(node.right, allowed_names)
    elif isinstance(node, ast.UnaryOp):
        if not isinstance(node.op, (ast.UAdd, ast.USub)):
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
        _validate_formula_ast(node.operand, allowed_names)
    else:
        raise ValueError(f"Unsupported node type: {type(node).__name__}")


def _evaluate_formula_ast(node, variables):
    """Safely evaluate a validated formula AST."""
    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Name):
        return variables[node.id]
    elif isinstance(node, ast.BinOp):
        left = _evaluate_formula_ast(node.left, variables)
        right = _evaluate_formula_ast(node.right, variables)
        if isinstance(node.op, ast.Add):
            return left + right
        elif isinstance(node.op, ast.Sub):
            return left - right
        elif isinstance(node.op, ast.Mult):
            return left * right
        elif isinstance(node.op, ast.Div):
            if right == 0:
                raise ValueError("Division by zero")
            return left / right
        elif isinstance(node.op, ast.Mod):
            return left % right
        elif isinstance(node.op, ast.Pow):
            # Cap exponent to prevent DoS
            if isinstance(right, (int, float)) and right > 100:
                raise ValueError("Exponent too large")
            return left ** right
    elif isinstance(node, ast.UnaryOp):
        operand = _evaluate_formula_ast(node.operand, variables)
        if isinstance(node.op, ast.UAdd):
            return +operand
        elif isinstance(node.op, ast.USub):
            return -operand
    raise ValueError(f"Unsupported node type: {type(node).__name__}")
```

## Explanation

The fix replaces `eval()` with safe AST-based parsing and evaluation. Instead of executing arbitrary code, the expression is parsed into an abstract syntax tree which is validated against an allowlist of safe node types (constants, variables, and binary/unary operators). An AST validator ensures only known-safe operations are present and variable names match the supplied `variables` dictionary. A custom evaluator then safely walks the validated tree and computes the result. This eliminates code injection while preserving the formula evaluation functionality. The implementation also includes input length validation and exponent capping to prevent denial-of-service attacks. Per the CWE-94 Python guidance, CPython has no sandbox for `eval()`, so the restriction of `__builtins__` does not prevent access to all builtins through introspection paths; the AST-based approach is the correct solution.

## Behaviour changes

The fix changes the following behaviors compared to the original:

1. **Invalid expressions now raise `ValueError`** instead of being executed as code. The original would execute any valid Python code, but the fix only accepts formulas with constants, variables, and the allowed operators (+, -, *, /, %, **).

2. **Variable names are validated** against the supplied `variables` dictionary. The original could access module globals or other builtins if syntax were crafted; the fix ensures only the explicitly provided variables are accessible.

3. **Input length is limited to 1000 characters** to prevent denial-of-service attacks from deeply nested or extremely long expressions that could exhaust memory or the call stack.

4. **Exponents larger than 100 are rejected** to prevent computational denial-of-service (e.g., `9 ** 9 ** 9` causing computation to hang).

5. **Unsupported operations fail explicitly** (e.g., function calls, attribute access, list operations, etc.) rather than being executed. Supported operations are binary arithmetic (`+`, `-`, `*`, `/`, `%`, `**`) and unary operators (`+`, `-`).

These changes narrow the feature to formula evaluation only, closing all code injection paths while maintaining the core functionality for safe mathematical expressions with variables.
