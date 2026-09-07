## Verdict

CONFIRMED: CWE-94 code injection via `Function` constructor with untrusted input. Arbitrary JavaScript code can be executed through the formula expression parameter.

## Source

User-controlled input flows from the HTTP request body (`req.body.expression` in formulaController.js) into the formula evaluator without validation or sanitization.

## Fix

### File: formulaEngine.js

```javascript
'use strict';

const { Parser } = require('expr-eval');

function evaluateFormula(expression, order) {
  try {
    return Parser.evaluate(expression, { order });
  } catch (error) {
    throw new Error('Invalid formula: ' + error.message);
  }
}

module.exports = { evaluateFormula };
```

## Explanation

The original code used the `Function` constructor to dynamically create and execute code: `new Function('order', \`return (${expression});\`)`. This is vulnerable to code injection because any JavaScript code injected through `req.body.expression` executes with full application privileges.

The fix replaces the `Function` constructor with the `expr-eval` library's `Parser.evaluate()` method. This library parses the input string and evaluates it only as an expression, preventing arbitrary code execution. The expression is restricted to valid expression syntax (arithmetic operations, variable access, function calls from a safe set) and cannot execute statements or access the global scope beyond what is passed in the evaluation context. The `order` object is made available in the evaluation scope as a variable, maintaining the original interface while preventing injection.

Error handling wraps parse/evaluation failures in a controlled exception, preventing information disclosure.

## Behaviour changes

- The formula expression is now restricted to safe expression evaluation only; statements (e.g., function declarations, loops, assignments) are no longer supported
- Invalid expressions now throw a controlled error message instead of a syntax error
- The `order` variable is available in the expression scope as before, but the expression is evaluated safely through the parser's AST-based mechanism rather than string interpolation into generated code
- Dependencies: requires `expr-eval` package to be installed
