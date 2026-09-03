## Verdict

CONFIRMED. CWE-94 code injection vulnerability present due to unsafe use of `eval()`.

## Source

```python
def evaluate_formula(expression, variables):
    context = dict(variables)
    # SAST FINDING: CWE-94 (Code Injection) reported here. Sink is the next statement.
    return eval(expression, {"__builtins__": {}}, context)
```

## Fix

Replace `eval()` with a safe formula evaluation library that does not execute arbitrary code. Use `numexpr` for mathematical expressions or `ast.literal_eval` for safe literal values only:

```python
import ast
import operator

def evaluate_formula(expression, variables):
    # For safe literal evaluation only (numbers, strings, lists, dicts, tuples, booleans, None)
    try:
        return ast.literal_eval(expression)
    except (ValueError, SyntaxError):
        pass
    
    # For mathematical expressions with variables, use a purpose-built safe evaluator
    # or import a library like numexpr that safely evaluates NumPy expressions
    import numexpr
    return numexpr.evaluate(expression, local_dict=variables)
```

For Python 3.13+, prefer `ast.literal_eval()` combined with a purpose-built expression evaluator. Alternatively, use libraries like `safe_eval`, `simpleeval`, or `numexpr` depending on the required expression syntax.

## Explanation

The vulnerability exists because `eval()` executes arbitrary Python code even when `__builtins__` is restricted to an empty dictionary. This restriction is an incomplete sandbox—attackers can still access dangerous classes and functions through object introspection. For example:

```python
().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['system']('rm -rf /')
```

bypasses the `__builtins__` restriction entirely, allowing arbitrary system command execution or data exfiltration.

**Why the fix works:** The `ast.literal_eval()` function only evaluates literal Python data structures (strings, numbers, tuples, lists, dicts, sets, booleans, None) and immediately raises an exception if the input contains function calls, variable references, or any executable code. For mathematical formulas with variables, `numexpr` safely evaluates NumPy array expressions using a dedicated parser that does not execute arbitrary Python code.

**Key principle:** Never use `eval()` or `exec()` on untrusted input. Use purpose-built parsers and evaluators that enforce a whitelist of safe operations instead of attempting to blacklist dangerous ones.
