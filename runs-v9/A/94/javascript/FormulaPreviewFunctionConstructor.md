## Verdict

Confirmed. `evaluateFormula` builds a `Function` constructor body by string-interpolating the caller-supplied `expression` directly into source code, then invokes it. `Function`, like `eval`, compiles and runs arbitrary JavaScript with access to the enclosing global scope (`this`, `require` via closures, `process`, etc. depending on host). Any caller of `evaluateFormula` with an untrusted `expression` gets full code execution, not formula evaluation.

## Source

- Taint origin: `req.body.expression` in `formulaController.js` (`previewFormula`), an HTTP request body field fully controlled by the client. The only guard is `|| '0'`, which does not restrict content, just absence.
- Sink: `formulaEngine.js`, `new Function('order', \`return (${expression});\`)`. The expression is concatenated straight into the function body with no validation, escaping, or sandboxing, then the resulting function is called with a live `order` object.
- Flow: `formulaController.previewFormula` reads `req.body.expression` -> passes it unchanged to `evaluateFormula(expression, sampleOrder)` -> `evaluateFormula` compiles it via `new Function` and executes it, returning the result to the HTTP response.

Example payload: `expression = "(() => { process.mainModule.require('child_process').execSync('id'); return 1; })()"` (or any JS expression) runs with the privileges of the Node process instead of computing a formula.

## Fix

Replace the `Function`-constructor evaluation with a real, sandbox-free arithmetic expression parser/evaluator that never compiles or executes attacker-supplied source, and only ever resolves a fixed, whitelisted set of variable names against the `order` object.

```javascript
'use strict';

const { Parser } = require('expr-eval');

// expr-eval parses a restricted arithmetic/logical grammar (no function
// definitions, no property access beyond the scope object, no global
// identifiers) and evaluates it directly against a plain data scope -
// it never generates or runs JavaScript source.
const parser = new Parser();

// Only these identifiers are resolvable inside a formula; anything else
// (e.g. `process`, `require`, `this`) is an undefined-variable parse/eval
// error, not a reference into the real scope.
function buildScope(order) {
  return {
    total: Number(order.total) || 0,
    tax: Number(order.tax) || 0,
  };
}

function evaluateFormula(expression, order) {
  let expr;
  try {
    expr = parser.parse(expression);
  } catch (err) {
    throw new Error(`Invalid formula: ${err.message}`);
  }

  const scope = buildScope(order);
  try {
    return expr.evaluate(scope);
  } catch (err) {
    throw new Error(`Could not evaluate formula: ${err.message}`);
  }
}

module.exports = { evaluateFormula };
```

`formulaController.js` needs no change: `evaluateFormula` keeps the same signature (`expression`, `order`) and return shape, so `previewFormula` calls it exactly as before. Any malformed or disallowed expression now surfaces as a thrown `Error` (caught and turned into a 400/500 response by the route's existing error handling, or wrap the call in `previewFormula` in a try/catch if none exists) instead of running as code.

Add `expr-eval` to the project's dependency manifest at a current maintained release and track it going forward with the usual SCA/dependency-audit process. `expr-eval`'s parser supports the standard arithmetic, comparison, and boolean operators plus a small set of math functions, which comfortably covers "order formula" use cases like `(total + tax) * 1.1` without ever touching `eval`/`Function`.

## Explanation

The root problem is using a JavaScript-source-generating API (`new Function`) to evaluate what is really a small, closed arithmetic language. `new Function(body)` is equivalent to `eval` for these purposes: it compiles and runs whatever text it's given with the full expressive power of JavaScript, including reaching into the Node global/module scope through closures, so there is no string-level sanitization that can make it safe against arbitrary expressions - denylisting keywords like `require` or `process` is reliably bypassable (e.g. via `constructor`, computed property access, or `globalThis`).

The fix swaps the evaluation mechanism rather than trying to filter the input: `expr-eval` parses the expression against its own restricted grammar (arithmetic, comparison, a fixed function set) and only resolves identifiers by looking them up in the `scope` object passed to `evaluate()` - there is no code path from a formula string back into the JavaScript runtime's global scope, `require`, or `process`, because the library never generates or executes JavaScript source at all. Restricting the scope to `{ total, tax }` (coerced to `Number`) also means the formula cannot pivot into unrelated fields of a richer `order` object even if one is passed in later. This preserves the feature - end users typing arithmetic formulas over order totals - while eliminating the code-execution primitive.
