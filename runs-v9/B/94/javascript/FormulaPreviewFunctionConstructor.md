## Verdict

- **cwe_id**: CWE-94 (Improper Control of Generation of Code / Code Injection)
- **verdict**: exploitable
- **confidence**: high

## Source

- **Source**: `req.body.expression` — attacker-controlled HTTP request body field, read in `formulaController.js` line 6 (`const expression = req.body.expression || '0';`) with no validation, then passed unchanged into `evaluateFormula(expression, sampleOrder)` on line 9.
- **Sink**: `formulaEngine.js` line 4 — `const fn = new Function('order', \`return (${expression});\`);`, immediately invoked on line 5 (`return fn(order);`). The `Function` constructor compiles the attacker-supplied string as a full JavaScript function body and executes it synchronously with the caller's privileges (file system, environment variables, `process`, any in-scope modules).
- **Data flow**: HTTP request body -> `formulaController.previewFormula` -> `evaluateFormula` -> `new Function(...)(order)`. No sanitization, allowlisting, or AST validation occurs anywhere on this path, so the trace is a direct, unbroken source-to-sink flow.

## Fix

Library recommendation: the loaded CWE-94/JavaScript guidance names no specific library, but does describe the required technique — parse the expression and walk the AST against an allowlist of node types and operators, using a parser entry point that consumes the whole input (it warns specifically that `acorn.parseExpressionAt` stops at the first expression and silently ignores trailing code). `acorn` is a parser only — it never executes the source it parses — so it is used here strictly to obtain an AST for allowlisting, not as an evaluator. Add it to `package.json`; confirm the resolved version against SCA/dependency-check tooling before merging, since no minimum version is specified by the loaded guidance.

Vulnerable code (`formulaEngine.js`):

```javascript
'use strict';

function evaluateFormula(expression, order) {
  // VULNERABLE: compiles and executes attacker-controlled source text
  const fn = new Function('order', `return (${expression});`);
  return fn(order);
}

module.exports = { evaluateFormula };
```

Fixed code (`formulaEngine.js`):

```javascript
'use strict';

const acorn = require('acorn');

// Only the order fields the formula feature is meant to reference.
const ALLOWED_FIELDS = new Set(['total', 'tax']);
const ALLOWED_BINARY_OPS = new Set(['+', '-', '*', '/']);
const ALLOWED_UNARY_OPS = new Set(['+', '-']);

function applyBinary(operator, left, right) {
  switch (operator) {
    case '+': return left + right;
    case '-': return left - right;
    case '*': return left * right;
    case '/': return left / right;
    default: throw new Error(`Operator not allowed: ${operator}`);
  }
}

function evaluateNode(node, order) {
  switch (node.type) {
    case 'Literal':
      if (typeof node.value !== 'number') {
        throw new Error('Only numeric literals are allowed');
      }
      return node.value;
    case 'Identifier':
      if (!ALLOWED_FIELDS.has(node.name)) {
        throw new Error(`Unknown field: ${node.name}`);
      }
      return Number(order[node.name]) || 0;
    case 'BinaryExpression':
      if (!ALLOWED_BINARY_OPS.has(node.operator)) {
        throw new Error(`Operator not allowed: ${node.operator}`);
      }
      return applyBinary(
        node.operator,
        evaluateNode(node.left, order),
        evaluateNode(node.right, order)
      );
    case 'UnaryExpression':
      if (!ALLOWED_UNARY_OPS.has(node.operator)) {
        throw new Error(`Operator not allowed: ${node.operator}`);
      }
      return node.operator === '-'
        ? -evaluateNode(node.argument, order)
        : +evaluateNode(node.argument, order);
    default:
      // Rejects CallExpression, MemberExpression, NewExpression, arrow
      // functions, sequence expressions, template literals, etc.
      throw new Error(`Expression type not allowed: ${node.type}`);
  }
}

function evaluateFormula(expression, order) {
  // acorn.parse consumes the entire input as a Program, so (unlike
  // acorn.parseExpressionAt) trailing statements cannot be smuggled past it.
  const ast = acorn.parse(expression, { ecmaVersion: 2020, sourceType: 'script' });

  if (ast.body.length !== 1 || ast.body[0].type !== 'ExpressionStatement') {
    throw new Error('Expression must be a single formula');
  }

  return evaluateNode(ast.body[0].expression, order);
}

module.exports = { evaluateFormula };
```

`formulaController.js` needs no change: `evaluateFormula(expression, sampleOrder)` keeps the same signature and is still invoked the same way.

## Explanation

The sink compiled attacker-controlled text directly into a JavaScript function body via `new Function(...)` and executed it, so any request could run arbitrary code with the application's own privileges (e.g. `require('child_process').execSync('...')` via `this.constructor.constructor(...)`, reading `process.env`, etc.) — there was no code path that didn't eventually let the attacker choose what gets executed. The fix removes the evaluator entirely rather than trying to filter its input: `evaluateFormula` now parses the expression into an AST with `acorn.parse` (a full-program parse, so the entire string is consumed and nothing can hide after a semicolon) and then interprets that AST itself, one node at a time, accepting only numeric literals, the two known order-field identifiers (`total`, `tax`), and the four arithmetic operators plus unary +/-. Every other node type — calls, member access, `new`, template literals, assignments, arrow functions — falls into the `default` branch and throws instead of running. Because no attacker-supplied text is ever handed to `eval`, `Function`, or any other JavaScript-executing API, there is no code-injection surface left: the worst an attacker can do is supply an expression that fails to parse or references an unknown identifier, both of which throw a plain `Error`.

## Behaviour changes

- The expression language is now arithmetic-only (numeric literals, the identifiers `total`/`tax`, `+ - * /`, and unary +/-) instead of full JavaScript. Any formula that used string operations, comparisons, function calls, or other order fields will now throw `Expression type not allowed` / `Unknown field` instead of evaluating. This restriction is the fix itself — it is what removes the code-execution surface — not an incidental side effect.
- Identifiers are checked against an explicit allowlist (`total`, `tax`) taken from the fields the sample order in `formulaController.js` actually uses, rather than being resolved as arbitrary property lookups on `order`. If the real order schema needs more fields exposed to formulas, they must be added to `ALLOWED_FIELDS` explicitly. This is the assumption made in autonomous mode: the two-field allowlist is derived from the only fields visible in the provided call chain (`sampleOrder = { total: 42, tax: 3 }`); a production order object may have additional legitimate fields that would need adding.
- The return value is now always a JS `number` (or the call throws), whereas the original could return whatever the compiled expression produced (a string, boolean, object, `undefined`, etc.). This narrowing is required by evaluating only an arithmetic grammar and matches the feature's apparent purpose (previewing a numeric formula).
- Failure mode is preserved at the same granularity: the original threw a `SyntaxError` synchronously out of `evaluateFormula` for malformed input (uncaught, since `formulaController.js` has no try/catch around the call), and the fixed version likewise throws a plain `Error` synchronously out of `evaluateFormula` for malformed or disallowed input — propagation to the caller/Express error handler is unchanged.
- New dependency added: `acorn` (parser only, does not execute the code it parses). No minimum version is supplied here; resolve and record it via SCA/dependency-check tooling before merging.
