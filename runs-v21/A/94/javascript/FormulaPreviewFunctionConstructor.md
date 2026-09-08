## Verdict

Confirmed CWE-94 vulnerability. The `new Function()` constructor at line 4 of formulaEngine.js executes dynamically generated code from the unsanitized `expression` parameter. An attacker can inject arbitrary JavaScript code, gaining full access to the application runtime, environment variables, and sensitive data.

## Source

- **File**: formulaEngine.js
- **Line**: 4
- **Vulnerable Code**: `const fn = new Function('order', `return (${expression});`);`
- **Data Flow**: 
  1. `formulaController.js` receives `expression` from `req.body.expression` (user input)
  2. Passes it directly to `evaluateFormula(expression, ...)`
  3. `evaluateFormula()` uses `new Function()` to compile and execute the expression as source code

## Fix

### File: formulaEngine.js

```javascript
'use strict';

const { Parser } = require('expr-eval-fork');

function evaluateFormula(expression, order) {
  // Validate expression length as DoS prevention
  if (expression.length > 500) {
    throw new Error('Expression exceeds maximum length');
  }
  
  try {
    // Use expr-eval-fork to safely parse and evaluate
    const parser = new Parser();
    const expr = parser.parse(expression);
    
    // Pass only primitive values from order object to prevent prototype pollution
    const scope = {};
    for (const [key, value] of Object.entries(order)) {
      if (typeof value === 'number' || typeof value === 'string' || typeof value === 'boolean') {
        scope[key] = value;
      }
    }
    
    return expr.evaluate(scope);
  } catch (error) {
    throw new Error(`Formula evaluation failed: ${error.message}`);
  }
}

module.exports = { evaluateFormula };
```

## Explanation

The fix replaces the unsafe `new Function()` constructor with `expr-eval-fork`, a maintained, security-focused expression evaluator. This closes the code injection vulnerability by:

1. **Removing dynamic code compilation**: No longer generates JavaScript source code from user input.

2. **Using safe expression parsing**: `expr-eval-fork` 3.0.0+ (the maintained fork of expr-eval) safely parses mathematical expressions into ASTs and evaluates them without executing arbitrary code. The original `expr-eval` package has known vulnerabilities (CVE-2025-12735); this fix uses the maintained version.

3. **Restricting scope values to primitives**: Only passes `number`, `string`, and `boolean` values in the scope object, preventing object injection and prototype pollution attacks.

4. **Length validation**: Limits expression length to 500 characters as denial-of-service prevention.

5. **Error handling**: Wraps evaluation errors to provide feedback without exposing system internals.

The controller (formulaController.js) requires no changes; it already passes the expression correctly to the fixed evaluator.
