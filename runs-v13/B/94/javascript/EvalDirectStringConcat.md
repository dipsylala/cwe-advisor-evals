## Verdict

Valid. Untrusted user input from `req.body.expression` is concatenated directly into a string and passed to `eval()`, which executes arbitrary JavaScript code with full access to the application's runtime, environment, and internals.

## Source

**Vulnerable sink:** Line 15, `eval('(' + expression + ')')`

**Data flow:**
1. Source: `req.body.expression` - untrusted HTTP request parameter
2. Validation: Lines 8-10 check only type (`string`) and non-zero length; no content validation
3. Sink: Expression string concatenated and passed to `eval()`

An attacker sending `"const os = require('os'); os.system('whoami')"` as the expression parameter executes arbitrary code with the application's privileges.

## Fix

Replace `eval()` with a purpose-built math expression evaluator. Using the `expr-eval` library:

**Dependencies:** Add `expr-eval` to `package.json`

```json
{
  "dependencies": {
    "expr-eval": "^2.2.0"
  }
}
```

**Fixed code:**

```javascript
'use strict';

const { Parser } = require('expr-eval');

// Express handler for POST /api/calculator/evaluate
// Body: { expression: "12 * (3 + 4)" }
function evaluateExpression(req, res) {
  const expression = req.body.expression;

  if (typeof expression !== 'string' || expression.length === 0) {
    return res.status(400).json({ error: 'expression is required' });
  }

  try {
    // Parse and compile the expression using a safe math evaluator
    const parser = new Parser();
    const compiled = parser.parse(expression);
    const result = compiled.evaluate();

    res.json({ result });
  } catch (err) {
    // Parse errors or evaluation errors
    return res.status(400).json({ error: 'Invalid expression' });
  }
}

module.exports = { evaluateExpression };
```

## Explanation

The fix eliminates code injection by replacing `eval()` with `expr-eval`, a purpose-built math expression parser that:

1. **Parses, does not execute:** The library parses the input into an abstract syntax tree (AST) and validates it at parse time, rejecting any syntax that isn't a mathematical expression.
2. **Restricts operations:** Only math operators (`+`, `-`, `*`, `/`, `%`, `^`), functions (`sin`, `cos`, `sqrt`, etc.), and literal values are allowed. Function calls to arbitrary code like `require()` or property access to `process` are rejected at parse time.
3. **No runtime scope access:** The evaluator has no access to the application's runtime scope, environment variables, or `require()`.

The try-catch block handles both parse errors (malformed input) and evaluation errors (e.g., division by zero), returning a 400 error with a generic message to prevent information leakage.

## Behaviour changes

- **Stricter parsing:** Invalid mathematical expressions now fail at parse time with a clear error, rather than potentially executing as JavaScript code.
- **No function scope leakage:** Expressions can no longer access the application's runtime scope, imports, or environment.
- **Limited operations:** Only mathematical operations are permitted; attempts to call methods or access properties are rejected.
- **Error handling:** Changed from potential runtime eval errors to parse-time validation errors, improving predictability.
- **Performance:** Compiled expressions may evaluate faster than `eval()` for repeated calculations, though this is a minor benefit.
