## Verdict

Exploitable

## Source

**Untrusted input**: `req.body.expression` received in formulaController.js line 6 from HTTP request body  
**Intermediate**: Passed to `evaluateFormula(expression, sampleOrder)` at formulaController.js line 9  
**Sink**: Template string interpolation into `new Function()` constructor at formulaEngine.js line 4

## Fix

**Vulnerable Code (formulaEngine.js):**
```javascript
'use strict';

function evaluateFormula(expression, order) {
  const fn = new Function('order', `return (${expression});`);
  return fn(order);
}

module.exports = { evaluateFormula };
```

**Fixed Code (formulaEngine.js):**
```javascript
'use strict';

const { Parser } = require('expr-eval');

function evaluateFormula(expression, order) {
  try {
    const expr = Parser.parse(expression);
    return expr.evaluate(order);
  } catch (error) {
    throw new Error(`Invalid formula: ${error.message}`);
  }
}

module.exports = { evaluateFormula };
```

**Installation**: Add `expr-eval` to package.json dependencies. Verify the resolved version through dependency-check tooling before deploying.

## Explanation

The vulnerability occurs because `new Function()` dynamically compiles and executes the untrusted expression parameter as JavaScript source code. An attacker can inject arbitrary code such as `1); require('child_process').execSync('malicious-command'); (('` to achieve remote code execution with full application privileges. The fix replaces dynamic code generation with the `expr-eval` library, which safely parses mathematical expressions into an abstract syntax tree and evaluates them without executing arbitrary code. The library only allows mathematical operators, identifiers, and property access—it rejects function calls, require statements, and other dangerous operations. Error handling is preserved to catch and report invalid expressions.

## Behaviour changes

- **Error handling**: Invalid expressions now throw an `Error` with message `Invalid formula: ...` instead of `SyntaxError` from Function constructor. This is a safer, application-controlled error message.
- **Execution model**: Expression is parsed to an AST and evaluated rather than compiled to JavaScript code. The behavior is functionally equivalent for valid mathematical expressions but rejects code that would execute arbitrary functions or access forbidden globals.
- **Dependencies**: Requires `expr-eval` package. No changes to function signature or return type for valid expressions.
- **Performance**: Negligible difference for typical formula sizes; AST evaluation is comparable to direct function execution.

All valid mathematical formulas continue to work identically; only malicious code injections are blocked.
