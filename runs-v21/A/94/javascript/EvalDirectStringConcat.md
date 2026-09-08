## Verdict
The code on line 15 uses `eval()` to execute user-supplied input as JavaScript code without any sandboxing. This is a direct code injection vulnerability that allows an attacker to execute arbitrary code on the server by passing malicious expressions in the request body.

## Source
**File:** calculatorController.js  
**Line:** 15  
**Vulnerable code:**
```javascript
const result = eval('(' + expression + ')');
```

The `expression` parameter comes directly from user input (`req.body.expression`) and is passed to `eval()`. While the code validates that the expression is a non-empty string, this does not prevent code injection because `eval()` interprets any valid JavaScript as code.

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
    // Use math.js evaluate() to safely parse and evaluate mathematical expressions
    // without executing arbitrary code.
    const result = math.evaluate(expression);
    res.json({ result });
  } catch (error) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
}

module.exports = { evaluateExpression };
```

## Explanation
The fix replaces the dangerous `eval()` call with `math.js`, a well-maintained library designed specifically for safe mathematical expression evaluation. `math.evaluate()` parses the input as a mathematical expression only, preventing arbitrary code execution. An attacker can no longer inject code like `process.exit()` or `require('fs')` because the evaluator only interprets mathematical operations and symbols.

The try-catch block handles invalid mathematical expressions gracefully, returning a 400 error instead of crashing the server or exposing stack traces.
