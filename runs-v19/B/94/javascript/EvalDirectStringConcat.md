## Verdict

VULNERABLE. User-controlled input flows directly into `eval()` at line 15 without validation, enabling arbitrary code execution within the application's runtime context.

## Source

Untrusted input source: `req.body.expression` (HTTP request body parameter). The request handler accepts any string from the client without constraining what code may be evaluated.

## Fix

### File: calculatorController.js

```javascript
'use strict';

const { Parser } = require('expr-eval');

// Express handler for POST /api/calculator/evaluate
// Body: { expression: "12 * (3 + 4)" }
function evaluateExpression(req, res) {
  const expression = req.body.expression;

  if (typeof expression !== 'string' || expression.length === 0) {
    return res.status(400).json({ error: 'expression is required' });
  }

  try {
    // Use expr-eval to safely parse and evaluate the expression without executing arbitrary code
    const result = new Parser().parse(expression).evaluate();
    res.json({ result });
  } catch (error) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
}

module.exports = { evaluateExpression };
```

## Explanation

The fix replaces the dangerous `eval()` function with the `expr-eval` library, which provides a safe expression parser that evaluates mathematical operations only. The `Parser.parse()` method constructs an abstract syntax tree and validates the input before evaluation, rejecting any code that attempts method invocation, property access, or other non-mathematical operations. This eliminates the code injection vector while preserving the original functionality of evaluating arithmetic expressions. The try-catch block handles parse errors gracefully, returning a 400 status with an error message instead of allowing exceptions to propagate.

## Behaviour changes

- Invalid expressions now return a 400 Bad Request with a generic error message instead of throwing an uncaught exception.
- The evaluation context is restricted to mathematical operations and variables; arbitrary JavaScript code and built-in functions are no longer accessible.
- Requires `expr-eval` as a dependency (install via `npm install expr-eval`).
