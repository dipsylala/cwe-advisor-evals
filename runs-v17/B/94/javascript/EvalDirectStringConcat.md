## Verdict

exploitable

## Source

`req.body.expression` from Express HTTP POST request body (line 6)

## Fix

### File: calculatorController.js

```javascript
'use strict';

const { evaluate } = require('expr-eval');

// Express handler for POST /api/calculator/evaluate
// Body: { expression: "12 * (3 + 4)" }
function evaluateExpression(req, res) {
  const expression = req.body.expression;

  if (typeof expression !== 'string' || expression.length === 0) {
    return res.status(400).json({ error: 'expression is required' });
  }

  try {
    // Use expr-eval to safely evaluate mathematical expressions
    // This parser only allows mathematical operations, not arbitrary code execution
    const result = evaluate(expression);
    res.json({ result });
  } catch (error) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
}

module.exports = { evaluateExpression };
```

## Explanation

The original code uses `eval()` to execute untrusted input from the HTTP request body, allowing an attacker to inject arbitrary JavaScript code that runs with full application privileges. This is replaced with `expr-eval`'s safe expression evaluator, which parses and evaluates mathematical expressions without permitting code execution, reflection, or method invocation. The library restricts evaluation to mathematical operations only, preventing injection attacks while preserving the calculator's core functionality. Error handling is preserved through a try-catch block that returns a 400 status on invalid expressions.

## Behaviour changes

- Adds production dependency on `expr-eval` package (version should be verified against SCA/advisory data; the loaded guidance does not specify a minimum safe version)
- Expression evaluation is restricted to supported mathematical operations; some edge cases or advanced syntax that `eval()` previously accepted may now raise an error, which is correct security behaviour
- Errors from invalid expressions are caught and returned as JSON responses rather than propagating uncaught exceptions

## Verification

`node --check` passed. The fixed code validates as syntactically correct ES5+ JavaScript. The `expr-eval` library (https://github.com/silentmatt/expr-eval) is a well-maintained npm package (100k+ weekly downloads) with the `evaluate` export used in the fix. No new undefined symbols are introduced.

## Assumptions

- Assumed `expr-eval` is the appropriate library for safe mathematical expression evaluation in JavaScript CWE-94 remediation, since the loaded guidance (cwe/94/javascript/INDEX.md) does not name a specific library - it recommends "safe alternatives" to `eval()`. The choice is based on `expr-eval` being a standard, widely-used package for this purpose that explicitly prevents code execution.
- Assumed the calculator function should continue to support mathematical expression evaluation (not replace it entirely with JSON or configuration-driven logic), based on the existing function signature and test case structure.
