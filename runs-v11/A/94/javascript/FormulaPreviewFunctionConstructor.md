## Verdict
CWE-94 confirmed. The `evaluateFormula` function dynamically constructs JavaScript code by interpolating user-supplied `expression` into the Function constructor, enabling arbitrary code execution.

## Source
**formulaController.js**: `expression = req.body.expression` receives untrusted user input and passes it directly to `evaluateFormula()` without validation.

**formulaEngine.js line 4**: `const fn = new Function('order', `return (${expression});`);` constructs a function by string concatenation with the untrusted expression, allowing an attacker to break out of the intended formula syntax and execute arbitrary code.

## Fix
Replace the unsafe Function constructor with a safe expression parser. Use the `math.js` library (or equivalent safe math expression evaluator):

```javascript
// formulaEngine.js
'use strict';

const { evaluate } = require('mathjs');

function evaluateFormula(expression, order) {
  try {
    // Evaluate only as a mathematical expression with the provided scope
    const result = evaluate(expression, order);
    return result;
  } catch (error) {
    throw new Error('Invalid formula: ' + error.message);
  }
}

module.exports = { evaluateFormula };
```

The `mathjs` library safely parses mathematical expressions and only evaluates safe operations within the provided scope, preventing code injection entirely. It does not have access to the global scope or dangerous APIs.

## Explanation
The original code treats user-supplied formulas as JavaScript source code by passing them to the Function constructor. An attacker sending `"1; process.exit();"` or `"1; require('fs').readFileSync('/etc/passwd')"` would execute arbitrary code on the server.

Using a dedicated math expression parser (`math.js`) confines the attacker to safe mathematical operations. The parser tokenizes and evaluates expressions in isolation; it cannot reference functions, require modules, or execute statements outside the mathematical domain. The provided `order` object becomes the scope for variable access (e.g., `order.total`), but the attacker cannot access the global scope, Node.js APIs, or execute code.
