## Verdict

Exploitable. The untrusted `expression` parameter flows directly into `eval()` without validation or sandboxing, allowing arbitrary JavaScript code execution with full application privileges.

## Source

`req.body.expression` (HTTP POST request body) flows unsanitized to the `eval()` sink at line 15. An attacker can supply malicious JavaScript code in the `expression` parameter to execute arbitrary code within the application context.

## Fix

Replace `eval()` with a dedicated math expression parser. Use the `mathjs` library, which safely evaluates mathematical expressions without permitting arbitrary code execution.

**Vulnerable code (line 15):**
```javascript
const result = eval('(' + expression + ')');
```

**Fixed code:**
```javascript
const math = require('mathjs');

// Inside evaluateExpression function:
try {
  const result = math.evaluate(expression);
  res.json({ result });
} catch (error) {
  res.status(400).json({ error: 'Invalid expression' });
}
```

**Dependency addition:**
Add `mathjs` to `package.json`:
```
"mathjs": "^12.0.0"
```

## Explanation

`eval()` executes arbitrary JavaScript code, granting attackers access to the entire runtime, including file system APIs, environment variables, and application secrets. Replacing it with `math.js`'s `evaluate()` method eliminates this risk by restricting execution to mathematical expressions only. The library parses the input and evaluates only the AST nodes it recognizes (arithmetic operators, functions, variables), rejecting any attempt to invoke arbitrary functions, access properties, or execute code outside its allowed expression grammar. Error handling ensures invalid expressions are rejected gracefully without exposing stack traces.

## Behaviour changes

Valid mathematical expressions behave identically: `"12 * (3 + 4)"` evaluates to `84`. Invalid or malicious inputs that would previously execute are now rejected with a 400 error response. The parenthesis wrapping is no longer needed since `math.evaluate()` handles leading operators correctly.
