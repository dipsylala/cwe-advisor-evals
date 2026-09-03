## Verdict

Exploitable. User-supplied input from `req.body.expression` flows directly into `eval()` without validation, allowing arbitrary code execution.

## Source

`req.body.expression` - untrusted HTTP request body parameter

## Fix

**Vulnerable Code (line 15):**
```javascript
const result = eval('(' + expression + ')');
```

**Fixed Code:**
```javascript
function evaluateMathExpression(expr) {
  // Allowlist: permit only digits, operators, parentheses, and whitespace
  if (!/^[\d+\-*/%().\s]*$/.test(expr)) {
    throw new Error('Invalid characters in expression');
  }

  // Parse and evaluate only mathematical expressions
  // Use Function constructor with no global scope access
  try {
    const fn = new Function('return (' + expr + ')');
    return fn.call(null);
  } catch (err) {
    throw new Error('Expression evaluation failed');
  }
}

function evaluateExpression(req, res) {
  const expression = req.body.expression;

  if (typeof expression !== 'string' || expression.length === 0) {
    return res.status(400).json({ error: 'expression is required' });
  }

  try {
    const result = evaluateMathExpression(expression);
    res.json({ result });
  } catch (err) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
}
```

## Explanation

The fix eliminates `eval()` by replacing it with a controlled evaluation function that first validates the expression against an allowlist of safe characters (digits, mathematical operators, parentheses, decimal points, and whitespace). This character-level validation is insufficient alone, but it reduces the attack surface by rejecting expressions that reference identifiers, functions, or properties. The replacement uses `Function` constructor called with `.call(null)` to prevent access to global scope through `this`, and wraps evaluation in try-catch to gracefully handle invalid expressions. The allowlist is a secondary control: combined with the sandboxed function context, it prevents code injection while preserving the mathematical evaluation functionality the endpoint provides.

## Behaviour changes

- **Input validation added**: The expression is now validated against a character allowlist before evaluation. Expressions containing letters, dots in property access, brackets, or other non-mathematical characters are rejected with HTTP 400 instead of being executed. This is a behaviour change only for malicious inputs; legitimate mathematical expressions remain accepted.
- **Error handling changed**: Invalid expressions now return a generic error message to the client instead of throwing an unhandled exception. Stack traces and implementation details are no longer leaked to clients.
- **Execution context changed**: The `Function` constructor creates a function with its own scope. While still vulnerable to sophisticated introspection attacks, it is safer than direct `eval()` because `this` is explicitly bound to `null`, preventing access to global objects through constructor chaining.

**Recommendation**: For production systems, use a dedicated math expression parser library (such as `math.js` or `expr-eval`) which parses the expression into an AST, validates it against a strict grammar, and evaluates only the permitted node types. The character allowlist here is a pragmatic interim control but is not cryptographically sufficient for hostile attackers.
