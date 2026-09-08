## Verdict

exploitable

## Source

`req.body.expression` in `evaluateExpression` (Express handler for `POST /api/calculator/evaluate`), an attacker-controlled string with no constraint beyond "non-empty string" (line 6-10).

## Fix

### File: calculatorController.js

```javascript
'use strict';

const { Parser } = require('expr-eval-fork');

// Express handler for POST /api/calculator/evaluate
// Body: { expression: "12 * (3 + 4)" }
function evaluateExpression(req, res) {
  const expression = req.body.expression;

  if (typeof expression !== 'string' || expression.length === 0) {
    return res.status(400).json({ error: 'expression is required' });
  }

  // Parse and evaluate through a math-expression grammar instead of the
  // JS interpreter: the parser has no call, member-access, or identifier
  // resolution to reach anything outside the arithmetic grammar itself, so
  // attacker-supplied text cannot run arbitrary code.
  const result = Parser.evaluate(expression);

  res.json({ result });
}

module.exports = { evaluateExpression };
```

## Explanation

The handler passed the raw request body straight into `eval()`, so any JavaScript the caller supplied ran with full access to the process (`require`, `process`, the filesystem, etc.) rather than just the arithmetic the endpoint is documented to support. The fix replaces the JS interpreter with `expr-eval-fork`'s `Parser`, a dedicated arithmetic-expression grammar that has no call syntax, no member access, and no way to resolve an identifier to anything other than its own built-in numeric constants/functions or an explicitly supplied variable (none are supplied here) - there is no path from expression text to `require`, `process`, or a constructor chain, which a manual denylist or a stripped-down `vm` context cannot guarantee. `Parser.evaluate(expression)` is `expr-eval-fork`'s documented static entry point (`Parser.evaluate(exprString, variables?)`); the codebase does not already depend on this package, so it is a new dependency to add to `package.json` (`"expr-eval-fork": "^3.0.0"` - the original `expr-eval` line stopped at 2.0.2 and carries an unfixed arbitrary-code-execution/prototype-pollution advisory, CVE-2025-12735; confirm the resolved version against SCA tooling before merging). The prior parenthesis-wrapping workaround for a leading operator or bare literal is no longer needed - the grammar parses those directly (verified: `-5 + 2` -> `-3`).

## Behaviour changes

- Removed the `'(' + expression + ')'` wrapping: no longer needed because the new parser's grammar (unlike splicing text into a JS statement) handles a leading operator or bare literal natively. Verified equivalent output for a representative case (`-5 + 2` -> `-3`, matching what the wrapped `eval` produced).
- Failure behaviour on malformed input is unchanged in shape but not in error type: previously a malformed or malicious expression threw a JS `SyntaxError`/`ReferenceError`, uncaught, propagated to whatever Express error handling exists upstream (not present in this file); now `Parser.evaluate` throws a plain `Error` ("parse error ..." or "undefined variable: ...") on the same class of bad input, uncaught, propagated the same way. No try/catch was added, matching the original's lack of one.
- Capability change, inherent to closing the weakness: expressions that relied on JS semantics outside plain arithmetic (property/member access such as `Math.PI`, function calls other than the parser's own built-ins, control flow) now fail to parse instead of executing. Conversely, the parser's own built-in functions/constants (e.g. `sqrt(16)`, `PI`) now work as bare identifiers where they previously were undefined in `eval`'s scope and would have thrown - this is new but benign calculator functionality, not an added risk, since it stays inside the same restricted grammar.
- New dependency: `expr-eval-fork` is not currently in this project's `package.json` (no manifest present in the case files); it needs to be added (`^3.0.0` or later - the floor at which CVE-2025-12735 was fixed) and installed before this code runs.

## Verification

Ran `node --check` on the fixed file: passed (no syntax errors). Additionally, in a scratch directory outside the codebase, installed `expr-eval-fork@3.0.3`, loaded the fixed handler with a mock `res`, and exercised it: `12 * (3 + 4)` -> `{"result":84}`; `-5 + 2` -> `{"result":-3}` (confirms the parenthesis-wrapping removal is behaviour-preserving); an IIFE payload calling `process.mainModule.require('child_process').execSync('whoami')` threw `parse error [1:12]: Unknown character "{"` instead of executing; a `vm`-escape-style payload (`this.constructor.constructor("return process")()`) threw `parse error [1:17]: Expected TNAME` instead of executing. Both injection attempts were rejected at parse time with no code execution.

## Assumptions

- No `package.json` is present among the case files, so the dependency addition is described rather than shown as a manifest diff; the minimum version (`^3.0.0`) is the floor stated in the loaded JavaScript guidance for CWE-94, not a value recalled independently.
- `Parser.evaluate` (static method) was confirmed against the installed `expr-eval-fork@3.0.3` package rather than assumed from the guidance text alone.
