# CWE-94 Remediation: JavaScript - EvalDirectStringConcat

## Verdict

The vulnerability is confirmed and exploitable. Line 15 passes untrusted user input directly into `eval()` via string concatenation, allowing arbitrary JavaScript code execution with full access to the application's runtime, file system, and secrets.

## Source

**File**: `calculatorController.js`

**Data flow**:
- **Source**: `req.body.expression` (user-controlled HTTP request body)
- **Intermediate**: String concatenation `'(' + expression + ')'` 
- **Sink**: `eval()` on line 15

**Attack scenario**: An attacker can inject arbitrary JavaScript by supplying a malicious `expression` parameter:
```
expression: "1; require('child_process').execSync('rm -rf /')"
```

This would execute the injected code with the application's privileges, bypassing any attempted input validation.

## Fix

Replace the `eval()` sink with a safe expression parser (`expr-eval-fork`), which restricts evaluation to mathematical expressions only and prevents arbitrary code execution.

### File: calculatorController.js

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
    const parser = new Parser();
    const result = parser.parse(expression).evaluate({});
    res.json({ result });
  } catch (error) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
}

module.exports = { evaluateExpression };
```

**Dependency requirement**: Add `expr-eval-fork` (version 3.0.0 or later) to `package.json`:
```json
{
  "dependencies": {
    "expr-eval": "npm:expr-eval-fork@^3.0.0"
  }
}
```

Note: The original `expr-eval` package stopped maintenance at 2.0.2 and contains CVE-2025-12735 (arbitrary code execution). Use `expr-eval-fork` 3.0.0+ instead.

## Explanation

The original code used `eval()`, which executes arbitrary JavaScript code supplied by the attacker. This grants unrestricted access to the Node.js runtime, requiring no validation to exploit.

The fix replaces `eval()` with `Parser.parse().evaluate()` from `expr-eval-fork`, a maintained expression parser that:
- Parses the user-supplied string into an abstract syntax tree (AST)
- Restricts evaluation to arithmetic operators and basic functions
- Prevents access to `require()`, `process`, constructors, and other language introspection facilities
- Throws an error for any syntax that doesn't conform to the expression grammar

The `try-catch` block handles malformed expressions gracefully, returning a 400 error instead of crashing.

The empty object `{}` passed to `evaluate()` ensures no external variables or functions are accessible to the expression, following the guidance that only primitive values should be passed to the variables parameter.

For expressions requiring Math functions (Math.sin, Math.sqrt, etc.), they are supported natively by the parser's grammar and do not require passing Math as a variable.

## Behaviour changes

- **Expressions now restricted**: Only arithmetic expressions and mathematical operations are supported. Expressions like `12 * (3 + 4)` work correctly. Attempts to call functions like `require()` or access `process` will throw a parse error.
- **Error handling**: Invalid expressions now return a 400 HTTP response with `{ error: 'Invalid expression' }` instead of crashing the application with an uncaught exception.
- **No code execution**: The fix completely eliminates code injection risk; user input is evaluated only as data within a sandboxed expression grammar, not as executable code.

**Syntax verification**: Syntax check passed with `node --check`.
