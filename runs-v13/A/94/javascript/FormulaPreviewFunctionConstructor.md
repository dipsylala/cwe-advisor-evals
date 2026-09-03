## Verdict
Confirmed and Fixed

## Source
**formulaEngine.js (line 4):**
```javascript
const fn = new Function('order', `return (${expression});`);
```

**Call chain:** `formulaController.js` passes user-supplied `req.body.expression` to `evaluateFormula()`, which constructs arbitrary code via the `Function` constructor.

## Fix
Replace the `Function` constructor with a safe expression parser. Using `expr-eval` or `math.js`:

```javascript
'use strict';

const { evaluate } = require('expr-eval');

function evaluateFormula(expression, order) {
  const parser = new evaluate.Parser();
  const ast = parser.parse(expression);
  return ast.evaluate(order);
}

module.exports = { evaluateFormula };
```

Alternatively, if a smaller footprint is needed, use `math.js`:
```javascript
'use strict';

const { evaluate } = require('mathjs');

function evaluateFormula(expression, order) {
  return evaluate(expression, order);
}

module.exports = { evaluateFormula };
```

Both libraries safely parse and evaluate expressions without executing arbitrary JavaScript code.

## Explanation
The original code uses `new Function()` to dynamically create a function from unsanitized user input. This is a direct code injection vulnerability (CWE-94) that allows an attacker to execute arbitrary JavaScript, potentially accessing sensitive data, modifying state, or compromising the server.

The fix replaces dynamic code generation with a dedicated expression parser designed for safe evaluation. These libraries:
- Parse expressions into an AST before evaluation
- Restrict operations to mathematical and logical expressions
- Prevent access to global objects, prototypes, or dangerous methods
- Raise syntax errors for invalid input rather than executing it

The fix preserves the intended functionality (evaluating formulas against order data) while eliminating the arbitrary code execution vector.
