## Verdict
VULNERABLE

## Source
Line 15 of calculatorController.js concatenates user-supplied input directly into a string passed to `eval()`:
```javascript
const result = eval('(' + expression + ')');
```
The `expression` variable is obtained from `req.body.expression` without validation against code injection. An attacker can inject arbitrary JavaScript that executes in the application's context.

## Fix

### File: calculatorController.js
```javascript
'use strict';

const math = require('mathjs');

// Express handler for POST /api/calculator/evaluate
// Body: { expression: "12 * (3 + 4)" }
function evaluateExpression(req, res) {
  const expression = req.body.expression;

  if (typeof expression !== 'string' || expression.length === 0) {
    return res.status(400).json({ error: 'expression is required' });
  }

  try {
    const result = math.evaluate(expression);
    res.json({ result });
  } catch (err) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
}

module.exports = { evaluateExpression };
```

## Explanation
The vulnerability stems from passing user input directly to `eval()`, which executes arbitrary JavaScript. The fix replaces `eval()` with `mathjs.evaluate()`, a purpose-built expression parser that safely evaluates mathematical expressions without code execution risks.

`mathjs` is a maintained library that parses and evaluates mathematical expressions according to a defined grammar; it does not execute arbitrary code. The try-catch block handles parse errors gracefully by returning a 400 response for invalid expressions, preventing information leakage while maintaining the intended functionality of evaluating mathematical expressions.

This approach eliminates the injection vector while preserving the application's capability to evaluate mathematical expressions from user input.
