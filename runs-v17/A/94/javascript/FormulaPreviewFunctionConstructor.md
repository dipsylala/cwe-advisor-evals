## Verdict

**VULNERABLE** - CWE-94: Improper Control of Generation of Code

The `new Function()` constructor at line 4 of formulaEngine.js receives unsanitized user input from `req.body.expression` and uses it to dynamically generate and execute arbitrary JavaScript code, allowing code injection and remote code execution.

## Source

**formulaController.js (line 6):** User input accepted from HTTP request body without validation
```javascript
const expression = req.body.expression || '0';
```

**formulaEngine.js (line 4):** Unsanitized user input injected directly into Function constructor
```javascript
const fn = new Function('order', `return (${expression});`);
```

An attacker can inject arbitrary code. Example payload:
```
expression: "order.total; require('child_process').exec('rm -rf /'); 1"
```

This would generate and execute code that runs system commands in the server process.

## Fix

### File: formulaEngine.js

```javascript
'use strict';

const math = require('mathjs');

function evaluateFormula(expression, order) {
  const compiled = math.compile(expression);
  return compiled.evaluate(order);
}

module.exports = { evaluateFormula };
```

## Explanation

The fix replaces the unsafe `Function` constructor with `math.js`, a widely-used library for safe mathematical expression evaluation. 

**Why this is safe:**
- `math.compile()` parses the expression into an Abstract Syntax Tree using a controlled grammar that only allows mathematical operations, variable references, and built-in functions
- No arbitrary JavaScript code generation or evaluation occurs
- The expression cannot break out of the mathematical context to access `require()`, `eval()`, or other dangerous globals
- The `evaluate()` method executes only within the provided scope (the `order` object)

**Why the original was unsafe:**
- Template literals directly interpolate user input into code
- The `Function()` constructor treats the resulting string as executable JavaScript
- Backtick escaping and semicolon injection allow arbitrary code to be appended

**Dependency:**
The fix requires `math.js` to be installed: `npm install mathjs`. This is a maintained, popular package (35M+ weekly downloads) explicitly designed for safe expression evaluation in Node.js and browsers.
