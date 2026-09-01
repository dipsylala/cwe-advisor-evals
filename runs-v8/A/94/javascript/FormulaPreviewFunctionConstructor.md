## Verdict
The vulnerability is confirmed. Line 4 of `formulaEngine.js` uses the `Function` constructor with unsanitized user input, enabling arbitrary code execution.

## Source
The `previewFormula` function in `formulaController.js` reads `expression` from `req.body.expression` and passes it directly to `evaluateFormula()`. The `evaluateFormula()` function interpolates this user-controlled input into a code string passed to the `Function` constructor, which compiles and executes arbitrary JavaScript.

## Fix
Replace the `Function` constructor with a safe math expression evaluator. Install `mathjs` and update `formulaEngine.js`:

```javascript
'use strict';

const math = require('mathjs');

function evaluateFormula(expression, order) {
  try {
    const scope = {
      total: order.total,
      tax: order.tax
    };
    return math.evaluate(expression, scope);
  } catch (error) {
    throw new Error('Invalid formula');
  }
}

module.exports = { evaluateFormula };
```

## Explanation
The `mathjs` library provides a safe expression parser that evaluates mathematical expressions without executing arbitrary code. By passing an explicit scope object containing only the allowed variables (`total` and `tax`), the fix prevents access to global objects or built-in functions. The try-catch block ensures invalid expressions fail gracefully rather than crashing. The `Function` constructor approach creates an uncontrolled code generation surface where any string—including system calls or data exfiltration—becomes executable JavaScript. This replacement eliminates that surface by treating the input as a mathematical expression, not code to compile.
