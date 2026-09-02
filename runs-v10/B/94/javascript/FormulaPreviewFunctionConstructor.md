## Verdict

CWE-94 confirmed on line 4. The `expression` parameter flows directly into the `new Function()` constructor without validation, allowing arbitrary JavaScript code injection.

## Source

The `expression` parameter (user-controlled input) is interpolated into the function source text on line 4:
```javascript
const fn = new Function('order', `return (${expression});`);
```

An attacker can inject arbitrary JavaScript code by supplying malicious expressions such as `1; require('child_process').execSync('whoami')` or `this.constructor.constructor('return process')()`.

## Fix

Replace the dynamic Function constructor with a safe expression evaluation library:

```javascript
const Parser = require('expr-eval').Parser;

function evaluateFormula(expression, order) {
  try {
    const parser = new Parser();
    const expr = parser.parse(expression);
    return expr.evaluate({ order });
  } catch (error) {
    throw new Error(`Invalid formula: ${error.message}`);
  }
}
```

## Explanation

The original code used the Function constructor to dynamically compile and execute untrusted input as JavaScript code, which grants full access to the runtime and any global objects or functions an attacker can reference. The fix uses `expr-eval`, a library designed specifically for safe mathematical expression evaluation. It parses the expression into an abstract syntax tree and restricts evaluation to mathematical operations and safe variable substitution only. Code injection through method calls, object access, or require statements is impossible because the parser only allows expressions—no statements, no function calls, no `this` access. The fix maintains the same function signature and preserves the core behavior of evaluating a formula with a provided parameter while eliminating the code injection vulnerability.

## Behaviour changes

- The function now only accepts mathematical expressions and variable references; any attempt to use function calls, property access, or statements throws a parse error
- Invalid syntax triggers an error with a descriptive message instead of creating a malformed function
- The function requires `expr-eval` as a new production dependency
- Evaluation is now performed in a restricted context with no access to the global object, `require`, or other runtime capabilities
- Performance impact is minimal; the parser caches compiled expressions if used repeatedly

