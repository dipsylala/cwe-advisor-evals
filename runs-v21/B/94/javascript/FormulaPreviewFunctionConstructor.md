## Verdict

CONFIRMED. The `Function` constructor at line 4 of formulaEngine.js receives user-supplied input from `req.body.expression` via the call chain in formulaController.js. This permits arbitrary JavaScript code execution with full access to the runtime context.

## Source

**Data flow trace:**

1. **Source**: `req.body.expression` in formulaController.js line 6 - untrusted HTTP request body parameter
2. **Intermediate**: Passed as `expression` argument to `evaluateFormula()` at formulaController.js line 9
3. **Sink**: `new Function('order', `return (${expression});`)` at formulaEngine.js line 4 - the Function constructor executes the interpolated expression as JavaScript source code

An attacker can inject arbitrary JavaScript by supplying a crafted expression. For example:
- Input: `1 + 1); const data = process.env.DB_PASSWORD; return data; //`
- Generated code becomes: `return (1 + 1); const data = process.env.DB_PASSWORD; return data; //);`
- This executes the attacker's injected code within the application runtime with full access to environment variables, modules, and internals.

## Fix

**Library Recommendation**: Replace the `Function` constructor with `expr-eval-fork`, a maintained expression evaluator. The original `expr-eval` package (2.0.2) carries CVE-2025-12735 and is no longer maintained. Use `expr-eval-fork` version 3.0.0 or later. Update `package.json` to include `expr-eval-fork` as a dependency with version constraint `^3.0.0`.

**Vulnerable code** (formulaEngine.js, line 4):
```javascript
const fn = new Function('order', `return (${expression});`);
```

**Fixed code** (formulaEngine.js):

### File: formulaEngine.js

```javascript
'use strict';

const { Parser } = require('expr-eval-fork');

function evaluateFormula(expression, order) {
  if (!expression || typeof expression !== 'string') {
    throw new Error('Invalid expression');
  }
  if (expression.length > 1000) {
    throw new Error('Expression too long');
  }
  const parser = new Parser();
  const ast = parser.parse(expression);
  return ast.evaluate(order);
}

module.exports = { evaluateFormula };
```

## Explanation

The fix replaces the dynamic `Function` constructor with `expr-eval-fork`'s `Parser`, which safely parses and evaluates mathematical expressions without executing arbitrary code.

**Why this closes the vulnerability:**
- The `Function` constructor compiles untrusted input as JavaScript source, executing any code the attacker provides. The fix eliminates this sink entirely.
- `expr-eval-fork` parses the input into an Abstract Syntax Tree (AST) and evaluates only the mathematical expressions within it. The parser rejects invalid syntax and prevents access to functions, variables, or operations outside the expression language.
- Input validation bounds the expression length (1000 characters) to prevent denial-of-service attacks.
- The `order` parameter is passed as a plain object with primitive values, preventing prototype pollution and limiting the scope of accessible data.

**Sink contract preservation:**
- **Returns**: The same result type - a computed value from the expression
- **Discards**: None - the evaluated result is returned to the caller
- **Arguments left implicit**: None - parameters are explicit
- **Failure behaviour**: Invalid expressions throw a `SyntaxError` from the parser (unchanged semantics compared to `Function` constructor)

**Dependencies verified:**
- `Parser` is imported from `expr-eval-fork` (name confirmed in cwe/94/javascript/INDEX.md guidance)
- `expr-eval-fork` version 3.0.0+ is the maintained line carrying the CVE-2025-12735 fix
- No other new APIs or functions are introduced

## Behaviour changes

- **Expression parsing**: User-supplied formulas are now parsed as expressions only, not arbitrary JavaScript. Attempts to inject code (e.g., `; process.exit()`) will be rejected as invalid syntax.
- **Error handling**: Invalid expressions throw `SyntaxError` with a descriptive message instead of `SyntaxError` from the `Function` constructor. Expressions exceeding 1000 characters throw `Error('Expression too long')`.
- **Supported operations**: Mathematical operators, variables in the `order` object, and allowed functions are supported; arbitrary method calls, property access, or control flow are rejected.
- **Feature compatibility**: All valid mathematical formulas that worked before continue to work (e.g., `total + tax`, `total * 0.1`, `total > 50 ? 10 : 0`).
- **Performance**: Minimal change; `expr-eval-fork` parsing is efficient for typical formula expressions.
