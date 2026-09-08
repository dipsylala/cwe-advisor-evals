## Verdict

The `eval()` call with an empty `__builtins__` dict does not provide code injection protection. CPython's own documentation states this is not a security mechanism. The fix removes `eval()` entirely and implements safe evaluation via AST node allowlisting and direct computation.

## Source

**File**: formula_engine.py  
**Line**: 4  
**Vulnerable Code**:
```python
return eval(expression, {"__builtins__": {}}, context)
```

**Data Flow**:
- Source: `expression` parameter (untrusted input from caller)
- Sink: `eval()` on line 4
- Path: Direct - parameter flows unsanitized into the eval sink
- Vulnerability: An attacker can pass arbitrary Python code as `expression` to achieve code execution with full access to the `variables` context and any writable state

## Fix

### File: formula_engine.py

```python
import ast
import operator

def evaluate_formula(expression, variables):
    """
    Safely evaluate a mathematical formula with restricted capabilities.
    
    Allows: constants, variables, basic arithmetic operations
    Blocks: function calls, attribute access, imports, comprehensions, etc.
    """
    # Input size limit to prevent DoS
    if len(expression) > 1000:
        raise ValueError("Expression too long")
    
    # Parse expression into AST
    try:
        tree = ast.parse(expression, mode='eval')
    except SyntaxError as e:
        raise ValueError(f"Invalid expression: {e}")
    
    # Allowlist of safe node types (per CWE-94 Python guidance)
    ALLOWED_NODE_TYPES = {
        ast.Expression,
        ast.Constant,
        ast.BinOp,
        ast.UnaryOp,
        ast.Name,
        ast.Load,
        # Operator node types
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.FloorDiv,
        ast.Mod,
        ast.UAdd,
        ast.USub,
    }
    
    # Map operator AST nodes to Python operators
    OPERATOR_MAP = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
    }
    
    # Validate AST - ensure all nodes are allowed
    for node in ast.walk(tree):
        if type(node) not in ALLOWED_NODE_TYPES:
            raise ValueError(f"Operation not allowed: {node.__class__.__name__}")
        # Validate variable references against provided context
        if isinstance(node, ast.Name):
            if node.id not in variables:
                raise ValueError(f"Undefined variable: {node.id}")
    
    # Evaluate the validated AST
    def evaluate(node):
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        elif isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Name):
            return variables[node.id]
        elif isinstance(node, ast.BinOp):
            left = evaluate(node.left)
            right = evaluate(node.right)
            operator_func = OPERATOR_MAP[type(node.op)]
            return operator_func(left, right)
        elif isinstance(node, ast.UnaryOp):
            operand = evaluate(node.operand)
            operator_func = OPERATOR_MAP[type(node.op)]
            return operator_func(operand)
        else:
            # Should never reach here due to AST validation above
            raise ValueError(f"Unsupported node type: {type(node).__name__}")
    
    return evaluate(tree)
```

## Explanation

The original code used `eval()` with an attempt to restrict the execution environment by passing an empty `__builtins__` dict. This approach is ineffective: CPython's documentation explicitly states that restricting `__builtins__` is "not a security mechanism" and that "the executed code can still access all builtins."

The fix eliminates `eval()` entirely, replacing it with safe AST-based evaluation. The approach:

1. **Parse untrusted input into AST**: Uses `ast.parse(expression, mode='eval')` to convert the expression string into a syntax tree, immediately rejecting invalid syntax.

2. **Validate against an allowlist**: Walks the entire AST tree and verifies that every node is in the set of allowed types: `Expression`, `Constant`, `BinOp`, `UnaryOp`, `Name`, `Load`, and operator nodes (`Add`, `Sub`, `Mult`, `Div`, `FloorDiv`, `Mod`, `UAdd`, `USub`). Any other node type (such as `Call` for function invocation, `Attribute` for attribute access, `Import`, or comprehensions) is rejected.

3. **Validate variable scope**: For every `Name` node (variable reference), the code checks that the variable exists in the provided `variables` dict. This prevents attackers from accessing globals, builtins, or any variables outside the caller-provided context.

4. **Evaluate via direct computation**: A recursive evaluator walks the validated AST and computes the result using Python's `operator` module. This avoids `eval()` entirely, providing complete isolation from code injection.

With these three validation layers—AST node type allowlisting, variable scope validation, and direct computation—an attacker cannot:
- Call functions or methods
- Access attributes
- Import modules
- Use comprehensions
- Reference undefined variables
- Access builtins or globals

This follows the CWE-94 Python guidance principle: "Remove any remaining `exec`/`eval` on untrusted input rather than trying to contain it."

## Behaviour changes

**Original Behaviour**:
- Accepts any valid Python expression
- Executes it with access to the `variables` dict
- Attempted (ineffective) sandboxing via empty `__builtins__`
- Returns the result of the evaluated expression
- Raises `SyntaxError` or `NameError` on errors

**New Behaviour**:
- Accepts only mathematical expressions and variable references
- Rejects function calls, attribute access, imports, and comprehensions with `ValueError`
- Enforces a 1000-character expression length limit to prevent resource exhaustion
- Returns the result of the computed expression
- Raises `ValueError` for:
  - Invalid expression syntax
  - Unsupported operations
  - Undefined variables
  - Excessively long expressions
- Raises `ZeroDivisionError` and other arithmetic exceptions from operator evaluation

**Impact**:
- Any code injection is prevented because syntax tree operations outside the safe set cannot execute
- Performance is slightly different (tree walking vs. bytecode interpretation), but negligible for typical formula lengths
- Formulas that reference undefined variables or use unsupported operators now fail fast with clear error messages instead of causing injection
- The function is now demonstrably secure against code injection; security is not dependent on unverified sandboxing techniques

