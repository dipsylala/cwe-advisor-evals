## Verdict

CONFIRMED — `eval()` is used to evaluate untrusted user input (`expression` parameter) at line 4. Even with restricted `__builtins__`, `eval()` is unsafe because attackers can access object methods in the context or exploit other Python internals to execute arbitrary code. CWE-94 requires eliminating `eval()` entirely for untrusted input.

## Source

The vulnerable code uses `eval(expression, {"__builtins__": {}}, context)` where `expression` comes from user input. The restriction of `__builtins__` to an empty dict is insufficient; `eval()` remains a code-injection vector.

## Fix

### File: formula_engine.py

```python
from simpleeval import simple_eval

def evaluate_formula(expression, variables):
    context = dict(variables)
    return simple_eval(expression, names=context)
```

## Explanation

The fix replaces `eval()` with `simple_eval()` from the `simpleeval` library, which is purpose-built for safely evaluating mathematical and logical expressions. `simple_eval()` parses the expression string into an AST and executes only whitelisted operations (arithmetic, comparisons, function calls to safe functions), completely preventing code injection. The `names` parameter safely passes user-supplied variables without exposing Python's object model or any method-resolution chains that `eval()` would permit. This eliminates the attack surface while preserving the intended formula-evaluation functionality.

The `simpleeval` library is maintained and widely used for exactly this use case — sandboxed expression evaluation without code-execution risk.
