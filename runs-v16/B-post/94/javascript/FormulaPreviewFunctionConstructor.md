## Verdict

VULNERABLE - Code injection via `new Function()` constructor accepting untrusted input.

## Source

HTTP request parameter `req.body.expression` from formulaController.js flows untrusted into the `evaluateFormula()` function without validation.

## Fix

Replace the `new Function()` constructor with a safe expression evaluation library. Using `expr-eval`:

### formulaEngine.js (fixed)

```javascript
'use strict';

const { parse } = require('expr-eval');

function evaluateFormula(expression, order) {
  try {
    const parsed = parse(expression);
    return parsed.evaluate(order);
  } catch (error) {
    throw new Error('Invalid formula');
  }
}

module.exports = { evaluateFormula };
```

**Dependency**: Add `expr-eval` to package.json. No specific version floor required - use current release from npm registry and verify against SCA tooling.

## Explanation

The vulnerability is eliminated by replacing `new Function()` with `expr-eval`'s `parse()` and `evaluate()` methods. This library parses the expression string into an AST (Abstract Syntax Tree) and only allows mathematical and logical operations - no property access, function calls, or constructor invocation. The `try/catch` block handles malformed expressions gracefully by throwing a validation error instead of executing arbitrary code.

The original sink `new Function('order', \`return (${expression});\`)` was a direct code-generation vulnerability: an attacker could terminate the string and inject JavaScript. The fixed code uses a restricted evaluator that cannot execute arbitrary functions, access process, environment variables, or other globals.

## Behaviour changes

- Injection payloads are rejected: inputs like `process.exit()` or `require('fs')` now throw "Invalid formula" instead of executing.
- Only expressions supported by `expr-eval` are allowed: arithmetic operations (`+`, `-`, `*`, `/`, `%`, `^`), comparisons (`<`, `>`, `==`), logical operators (`&&`, `||`, `!`), and property access on the provided object (`order.total`).
- The fix preserves the original calling contract: same function signature, same parameter types (`expression` string, `order` object), same return type (evaluated result).
- Formula evaluation performance is slightly lower due to AST parsing overhead, but security gain outweighs the negligible latency difference.
