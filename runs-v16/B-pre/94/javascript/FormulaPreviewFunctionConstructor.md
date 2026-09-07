## Verdict

Exploitable. Untrusted user input from `req.body.expression` flows directly to the `Function()` constructor, allowing arbitrary code injection.

## Source

Data originates in `formulaController.js` at line 6: `const expression = req.body.expression || '0';` (user-supplied HTTP request body). This untrusted value is passed to `evaluateFormula()` at line 9 and reaches the vulnerable sink without validation.

## Fix

**Vulnerable code** (formulaEngine.js, lines 1–8):
```javascript
'use strict';

function evaluateFormula(expression, order) {
  const fn = new Function('order', `return (${expression});`);
  return fn(order);
}

module.exports = { evaluateFormula };
```

**Fixed code**:
```javascript
'use strict';

const { Parser } = require('expr-eval');

function evaluateFormula(expression, order) {
  try {
    const parser = new Parser();
    const expr = parser.parse(expression);
    return expr.evaluate(order);
  } catch (error) {
    throw new Error('Invalid expression');
  }
}

module.exports = { evaluateFormula };
```

## Explanation

The fix replaces the unsafe `Function()` constructor with `expr-eval`, a dedicated expression evaluator library designed to safely parse and evaluate mathematical expressions without executing arbitrary code. The `expr-eval` parser constructs an abstract syntax tree (AST) from the expression string and validates it before evaluation, rejecting any syntax containing function calls, property access outside the evaluation context, or other dangerous patterns. This eliminates the code injection vector entirely: the user-supplied expression is no longer treated as source code to be compiled and executed, but as data to be parsed and safely evaluated within a restricted scope.

The try-catch block handles malformed expressions by throwing a descriptive error instead of propagating parser exceptions, providing consistent error handling for invalid input.

## Behaviour changes

- **Return value**: Unchanged. The function still returns the evaluated result of the expression.
- **Error handling**: Changed. Invalid expressions now throw `Error('Invalid expression')` instead of letting the Function constructor throw its native error. This provides consistent error reporting and prevents exposure of parser internals.
- **Dependencies**: Introduces dependency on `expr-eval` package. The library must be installed as a project dependency (add to package.json).
- **Security boundary**: The `order` object is now the only variable in scope during evaluation; no access to global scope, `process`, `require`, or other Node.js internals is possible.
