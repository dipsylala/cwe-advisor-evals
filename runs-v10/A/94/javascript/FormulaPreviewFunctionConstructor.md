## Verdict
The code is vulnerable to CWE-94: Improper Control of Generation of Code. User-supplied input from `req.body.expression` flows directly into the Function constructor on line 4 of `formulaEngine.js`, allowing arbitrary code execution.

## Source
**File:** `formulaEngine.js`, line 4

```javascript
const fn = new Function('order', `return (${expression});`);
```

The `expression` parameter originates from untrusted user input (`req.body.expression` in `formulaController.js`), which is interpolated directly into the dynamically generated function string with no validation or sanitization.

**Attack Example:**
If a user supplies the expression `order.total; process.exit(1);`, the generated function becomes:
```javascript
function(order) { return (order.total; process.exit(1);); }
```
This executes arbitrary code beyond the mathematical expression.

## Fix
Replace the Function constructor with a safe expression parsing library. Use `math.js` for mathematical formula evaluation:

```javascript
'use strict';

const math = require('mathjs');

function evaluateFormula(expression, order) {
  const scope = { order };
  try {
    return math.evaluate(expression, scope);
  } catch (e) {
    throw new Error('Invalid formula: ' + e.message);
  }
}

module.exports = { evaluateFormula };
```

Then update `formulaController.js` to reference the order object properties correctly:

```javascript
'use strict';

const { evaluateFormula } = require('./formulaEngine');

function previewFormula(req, res) {
  const expression = req.body.expression || '0';
  const order = { total: 42, tax: 3 };

  try {
    const value = evaluateFormula(expression, order);
    res.json({ value });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
}

module.exports = { previewFormula };
```

In the expression, users can now safely reference order properties as `order.total` or `order.tax` within mathematical operations like `order.total * 2 + order.tax`, and `math.evaluate()` will evaluate only the mathematical expression without allowing arbitrary code execution.

## Explanation
The Function constructor is inherently dangerous when its code string is built from untrusted input, as it creates and executes arbitrary JavaScript code. This vulnerability allows attackers to escape the intended formula evaluation context entirely.

The fix uses `math.js`, a well-maintained library designed specifically for safe mathematical expression evaluation. It parses and evaluates expressions in a controlled manner without generating or executing arbitrary code. The library validates the syntax and only permits mathematical operations, preventing code injection.

The `scope` parameter provides controlled access to the `order` object, allowing formulas to reference order properties by name while maintaining a sandboxed evaluation environment. Error handling wraps evaluation failures, preventing stack trace leakage to the client.
