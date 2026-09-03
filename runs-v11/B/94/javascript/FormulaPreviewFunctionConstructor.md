## Verdict

Exploitable

## Source

User-controlled input from `req.body.expression` in `formulaController.js` line 6, passed unchecked to `evaluateFormula()`.

## Fix

**Vulnerable code:**

```javascript
function evaluateFormula(expression, order) {
  const fn = new Function('order', `return (${expression});`);  // CWE-94: code injection
  return fn(order);
}
```

**Fixed code:**

```javascript
const Parser = require('expr-eval').Parser;

function evaluateFormula(expression, order) {
  try {
    const parser = new Parser();
    const expr = parser.parse(expression);
    return expr.evaluate(order);
  } catch (err) {
    // Invalid expression - return default value
    return 0;
  }
}
```

## Explanation

The original code uses JavaScript's `Function` constructor to dynamically compile user input into executable code, granting attackers the ability to execute arbitrary JavaScript with full access to the application runtime, variables, and external modules. The fixed code replaces unsafe dynamic code generation with the `expr-eval` library, a purpose-built mathematical expression parser that safely evaluates expressions without code execution. `expr-eval` parses the input into an abstract syntax tree (AST) and evaluates only safe mathematical operations (arithmetic, comparisons, logical operators, member access through the provided context object), rejecting any attempt to invoke functions, reference prototypes, or access unauthorized properties. Error handling ensures that malformed expressions fail gracefully rather than crashing or executing partial code.

## Behaviour changes

- **Library dependency added:** Code now requires `expr-eval` as a dependency; add to `package.json` and verify the latest secure version against your SCA tooling.
- **Error handling changed:** Invalid expressions now return `0` instead of throwing a SyntaxError. If the application needs to distinguish invalid expressions from valid ones that evaluate to 0, wrap the try-catch and signal the error status separately (e.g., return `{ value: 0, valid: false }` for invalid input).
- **Expression language narrowed:** Only mathematical operations and member access on the context object (`order.total`, arithmetic operators, etc.) are now permitted. Expressions using function calls, `require()`, or other JavaScript constructs will be rejected. Verify that all legitimate formulas in production use only these safe operations.
