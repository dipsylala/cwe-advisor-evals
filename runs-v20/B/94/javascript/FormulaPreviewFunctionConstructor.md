## Verdict

exploitable

- **cwe_id**: CWE-94 (Improper Control of Generation of Code / Code Injection)
- **location**: `formulaEngine.js:4`, inside `evaluateFormula`
- **confidence**: high

## Source

`req.body.expression` in `formulaController.js:6` (`previewFormula`). This is the raw JSON body of an HTTP request handled by an Express-style route; it is fully attacker-controlled and is passed to `evaluateFormula` unmodified (the `|| '0'` fallback only covers the missing-field case, it does not validate or constrain a supplied string).

**Sink**: `formulaEngine.js:4` - `new Function('order', `return (${expression});`)`, immediately invoked as `fn(order)` on line 5. The request body's `expression` is spliced directly into the body of a dynamically compiled function and executed with the full capability of the Node.js runtime (module system, `process`, filesystem, network, etc.) - a textbook `Function`-constructor code-injection sink.

**Sink contract**:
- *Returns*: whatever the constructed function's `return` expression evaluates to; the controller serializes it as `{ value }` in the HTTP response.
- *Discards*: nothing beyond the return value; no side channel is intentionally suppressed.
- *Arguments left implicit*: `new Function` takes no execution-context restriction - it compiles in the global scope of the current realm, so the generated function has ambient access to everything module-scope code has access to (this is the vulnerability, not an omitted safety default).
- *Failure behaviour*: a malformed expression throws a `SyntaxError` at construction, or a runtime error/`ReferenceError` during invocation; `previewFormula` does not catch either, so it propagates to Express's default error handling.

No sanitization, allowlisting, or sandboxing occurs between source and sink, so the path is exploitable as reported.

## Fix

**Library recommendation**: `expr-eval-fork`, minimum safe version `3.0.0`. The original `expr-eval` package (last published 2.0.2, 2022) carries CVE-2025-12735 (CERT VU#263614: arbitrary code execution through an attacker-influenced variables object, plus prototype pollution) with no fixed release on that line; the maintained fork `expr-eval-fork` shipped the fix starting at 3.0.0. Add it to the project's `package.json` dependencies (e.g. `"expr-eval-fork": "^3.0.0"`) and confirm the resolved version against SCA/dependency-check tooling before merging, since none was supplied in the reviewed files.

### File: formulaEngine.js
```javascript
'use strict';

const { Parser } = require('expr-eval-fork');

// Maximum formula length accepted for preview evaluation, per CWE-94 guidance
// (bound the expression length/operator set even when using an AST-based evaluator).
const MAX_EXPRESSION_LENGTH = 200;

function evaluateFormula(expression, order) {
  if (typeof expression !== 'string' || expression.length === 0 || expression.length > MAX_EXPRESSION_LENGTH) {
    throw new Error('Invalid formula expression');
  }

  // Only primitive fields are exposed to the expression evaluator. Passing the
  // whole `order` object as a variable would let a formula reach its prototype
  // chain (e.g. order.constructor.constructor(...)); primitives close that off.
  const variables = {};
  if (order && typeof order === 'object') {
    for (const [key, value] of Object.entries(order)) {
      if (typeof value === 'number' || typeof value === 'string' || typeof value === 'boolean') {
        variables[key] = value;
      }
    }
  }

  return Parser.evaluate(expression, variables);
}

module.exports = { evaluateFormula };
```

## Explanation

The vulnerable code compiled attacker-supplied text directly into executable JavaScript via `new Function(...)`, so any request body could run arbitrary code in the server's process. The fix replaces the `Function`-constructor sink with `expr-eval-fork`'s `Parser.evaluate(expression, variables)`, which parses the expression into a restricted arithmetic/logic AST rather than compiling and running JavaScript - there is no grammar production that reaches `eval`, `require`, `process`, or any host object, so the injection class is closed at the mechanism level rather than by pattern-matching the input string. A second, narrower risk that the general "swap the evaluator" fix does not close by itself is passing an object into the evaluator's variables map: `expr-eval`'s historical CVE was exactly an attacker reaching an object's prototype chain through member access on a supplied variable. The fix avoids that by never exposing the `order` object itself to the parser - it copies only `order`'s own primitive-valued properties (`number`/`string`/`boolean`) into a fresh `variables` object, so there is no object reference in scope for a formula to call `.constructor` on. A length cap (`MAX_EXPRESSION_LENGTH`) is added as the defence-in-depth layer the guidance calls for on top of the AST-based evaluator itself.

## Behaviour changes

- **Formula syntax changes from `order.<field>` to bare `<field>`.** Because `order` is no longer passed to the evaluator as an object (to prevent the prototype-chain escape above), a formula that previously read `order.total - order.tax` must be rewritten as `total - tax`. This is a required, deliberate trade-off, not an oversight: keeping `order` as a member-accessible object would leave the constructor-chain escape open even under the fixed evaluator, per the loaded guidance ("even there, pass only primitive values in the variables object"). Any formulas already stored using the old `order.field` syntax will need to be migrated to the bare-field form.
- **Only primitive fields of `order` are reachable from a formula**; nested objects, arrays, or functions on `order` are silently omitted from `variables` and are not usable in an expression. The sample call site (`{ total: 42, tax: 3 }`) is all primitives, so this does not affect the reviewed call chain, but any future field added to the order object that is itself an object/array will not be exposed to formulas unless flattened first.
- **Expression grammar is now limited to `expr-eval-fork`'s supported operators/functions** (arithmetic, comparison, boolean logic, and its built-in math functions) rather than arbitrary JavaScript. Any legitimate formula relying on JS constructs outside that grammar (loops, object/array literals, arbitrary function calls) is no longer expressible and will need to be rewritten in the supported expression syntax.
- **A length cap of 200 characters and a non-empty/string type check are now enforced before parsing**; requests with an oversized, empty, or non-string `expression` now throw `Error('Invalid formula expression')` instead of reaching the evaluator. `previewFormula` does not currently catch this (it did not catch the original `SyntaxError`/`ReferenceError` either), so the failure still propagates to Express's default error handling as before - only the error type/message changes, from a V8 `SyntaxError`/`ReferenceError` to this explicit `Error` or an `expr-eval-fork` parse/evaluate error.
- **`fn(order)` becomes `Parser.evaluate(expression, variables)`** - the caller's signature (`evaluateFormula(expression, order)`) and return value contract (the numeric/primitive result of the expression) are unchanged; `formulaController.js` requires no modification.

**Verification**: `node --check` on the fixed file (copied to a scratch location) passed with no output/exit 0. Functionally verified against `expr-eval-fork@3.0.3` installed in the same scratch location: `evaluateFormula('total - tax', { total: 42, tax: 3 })` correctly returned `39`; an injection attempt using an IIFE calling `process.mainModule.require('child_process').execSync(...)` was rejected with a parse error (`Unknown character "{"`); an attempted prototype-chain escape (`total.constructor.constructor("return process")()`) was rejected with a parse error (`Expected TNAME`); and a 300+ character expression was rejected by the length guard before parsing.

**Assumptions**: the project's `package.json` was not part of the two-file call chain reviewed, so the `expr-eval-fork` dependency addition is stated as a required manifest change but the manifest itself was not edited here.
