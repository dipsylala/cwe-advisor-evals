## Verdict

Real. Line 15 uses `eval()` to execute user-supplied input from `req.body.expression` directly. This allows arbitrary JavaScript code execution.

## Source

```javascript
const result = eval('(' + expression + ')');
```

The `expression` parameter comes from untrusted user input and is concatenated directly into code passed to `eval()`, enabling code injection.

## Fix

```javascript
const { evaluate } = require('mathjs');
const result = evaluate(expression);
```

Replace `eval()` with a dedicated math expression parser. The `mathjs` library safely evaluates mathematical expressions without executing arbitrary code. Install with `npm install mathjs`.

## Explanation

`eval()` compiles and executes arbitrary JavaScript code, making it a code injection sink when the input is attacker-controlled. Even with type checking and length validation on the input, `eval()` still interprets the entire string as executable code.

The fix uses `mathjs.evaluate()`, which parses the expression into an abstract syntax tree, validates the structure, and computes only the mathematical result. It supports standard arithmetic operators (`+`, `-`, `*`, `/`, `^`) and functions without allowing arbitrary code execution. The library's built-in parser prevents injection by design — it interprets the input as mathematical notation, not JavaScript source code.

If `mathjs` is not available, alternative safe expression evaluators include `expr-eval` or `formula.js`, which provide similar sandboxed evaluation for mathematical expressions.
