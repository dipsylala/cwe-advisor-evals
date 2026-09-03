## Verdict
Confirmed exploitable. The vulnerability cannot be closed by restricting `__builtins__`. Python's eval() allows access to the full runtime environment through attribute access, class references, and introspection, bypassing the attempted sandbox.

## Source
The untrusted source is the `expression` parameter passed to `evaluate_formula()`. An attacker can supply arbitrary Python code as a string, and eval() will execute it with full access to:
- All builtin types and methods through class hierarchies (`().__class__.__bases__[0]...`)
- The `context` dictionary and any names it contains
- Module internals through attribute traversal

Example attack: `().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].exit()`

## Fix
Replace `eval()` with a safe expression parser using `ast.parse()` and an allowlist of safe node types:

```python
import ast
import operator

def evaluate_formula(expression, variables):
    # Parse the expression into an AST
    try:
        tree = ast.parse(expression, mode='eval')
    except SyntaxError as e:
        raise ValueError(f"Invalid expression: {e}")
    
    # Allowlist of safe node types for mathematical/formula expressions
    ALLOWED_NODES = {
        ast.Expression, ast.Constant, ast.BinOp, ast.UnaryOp,
        ast.Name, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow,
        ast.USub, ast.UAdd, ast.Mod, ast.FloorDiv
    }
    
    # Validate the AST contains only allowed nodes
    for node in ast.walk(tree):
        if type(node) not in ALLOWED_NODES:
            raise ValueError(f"Expression contains disallowed operation: {type(node).__name__}")
    
    # Compile and evaluate safely
    compiled = compile(tree, '<string>', 'eval')
    return eval(compiled, {"__builtins__": {}}, variables)
```

Alternative for numeric formulas only: use `ast.literal_eval()` with strict input validation (size and nesting limits), or use a third-party library like `numexpr` or `sympy` with an explicit restricted namespace.

## Explanation
The original code attempted to sandbox eval() by passing an empty `__builtins__` dictionary. This is not a security mechanism—CPython explicitly documents that overriding `__builtins__` does not prevent access to the full runtime through attribute chains and class introspection. The fixed code replaces this with an AST-based allowlist: the expression is parsed into an abstract syntax tree, validated to contain only safe node types (constants, basic arithmetic operators, variable names), and rejected if any unsafe construct appears (attribute access, function calls, imports, etc.). This approach:
1. Blocks the injection vector entirely by preventing code execution paths
2. Still allows legitimate mathematical/formula expressions
3. Follows the CWE-94 guidance for Python: "walk the tree against an allowlist of node types and operators, rejecting anything else"

## Behaviour changes
- **Rejected constructs**: attribute access (`obj.attr`), function calls (`func()`), subscripting (`dict[key]`), list/dict/set literals, lambda, comprehensions, imports, comparisons beyond basic operators—any construct not explicitly in the allowlist.
- **Allowed constructs**: numeric literals, string literals, variable names (looked up in `variables`), unary operators (`+x`, `-x`), binary operators (`+`, `-`, `*`, `/`, `**`, `%`, `//`).
- **Error handling**: malformed expressions raise `SyntaxError` (caught and re-raised as `ValueError`); expressions containing disallowed nodes raise `ValueError` with details of the blocked operation.
- **Return value**: same as original—the evaluated result of the expression as a Python object.
- **Performance**: negligible impact; AST parsing is fast for short expressions.
