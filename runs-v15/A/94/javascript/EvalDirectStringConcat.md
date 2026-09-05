## Verdict
CWE-94 code injection vulnerability confirmed. The code uses `eval()` to execute user-supplied mathematical expressions, allowing arbitrary code injection.

## Source
```javascript
const result = eval('(' + expression + ')');
```

The `expression` parameter comes directly from `req.body.expression` without any validation or sanitization before being concatenated into the eval string.

## Fix
Replace `eval()` with a dedicated mathematical expression parsing library. Use `math.js`, which safely evaluates mathematical expressions without executing arbitrary code.

Install the dependency:
```
npm install mathjs
```

Replace the vulnerable code with:
```javascript
const math = require('mathjs');

function evaluateExpression(req, res) {
  const expression = req.body.expression;

  if (typeof expression !== 'string' || expression.length === 0) {
    return res.status(400).json({ error: 'expression is required' });
  }

  try {
    const result = math.evaluate(expression);
    res.json({ result });
  } catch (error) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
}

module.exports = { evaluateExpression };
```

## Explanation
`eval()` executes any JavaScript code passed to it, making it unsuitable for evaluating untrusted input. An attacker could inject code like `"1) || process.exit() || (1"` or `"1) || require('child_process').exec('rm -rf /') || (1"` to cause arbitrary harm.

The `math.js` library provides a safe `evaluate()` function that parses and evaluates only mathematical expressions according to a grammar that excludes code execution primitives. It handles operator precedence, functions (sin, cos, etc.), and constants correctly while rejecting attempts to access arbitrary properties or execute functions.

The try-catch block handles parsing errors for invalid expressions, allowing the application to respond with a 400 error rather than crashing or executing unintended code.
