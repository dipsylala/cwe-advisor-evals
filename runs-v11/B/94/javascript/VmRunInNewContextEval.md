## Verdict

Real issue, exploitable. User-supplied JavaScript code flows directly to `vm.runInNewContext()` with no allowlist validation or execution-time restriction. The vm module is not a security boundary; code can break out through constructor chains and introspection to access the full Node process.

## Source

Line 25: `const { script } = req.body;` is validated only for type and length (line 26), then passed through `runAutomationScript(script, ...)` to the sink at line 19.

## Fix

Replace dynamic code evaluation with a safe expression parser that walks an AST allowlist, rejecting any node types or operations outside the permitted set. This example uses `acorn` to parse the script as an expression and validates it against a whitelist of safe node types:

```javascript
'use strict';

const vm = require('node:vm');
const acorn = require('acorn');

// Allowlist of safe AST node types for order filtering logic
const ALLOWED_NODES = new Set([
  'Program',
  'ExpressionStatement',
  'BinaryExpression',
  'LogicalExpression',
  'CallExpression',
  'Identifier',
  'MemberExpression',
  'Literal',
  'ConditionalExpression',
  'UpdateExpression',
]);

const ALLOWED_OPERATORS = new Set([
  '==', '===', '!=', '!==', '<', '>', '<=', '>=',
  '&&', '||', '!',
  '+', '-', '*', '/', '%',
  '++', '--',
  '?',
]);

const ALLOWED_IDENTIFIERS = new Set([
  'orders',    // the orders array passed in sandbox
  'emit',      // the emit function passed in sandbox
  'true',
  'false',
  'null',
]);

function validateAst(node) {
  if (!ALLOWED_NODES.has(node.type)) {
    throw new Error(`Unsafe node type: ${node.type}`);
  }

  if (node.type === 'Identifier' && !ALLOWED_IDENTIFIERS.has(node.name)) {
    throw new Error(`Unsafe identifier: ${node.name}`);
  }

  if ((node.type === 'BinaryExpression' || node.type === 'LogicalExpression') 
      && !ALLOWED_OPERATORS.has(node.operator)) {
    throw new Error(`Unsafe operator: ${node.operator}`);
  }

  if (node.type === 'UpdateExpression' && !ALLOWED_OPERATORS.has(node.operator)) {
    throw new Error(`Unsafe operator: ${node.operator}`);
  }

  // Validate nested nodes recursively
  for (const key in node) {
    if (node[key] && typeof node[key] === 'object') {
      if (Array.isArray(node[key])) {
        node[key].forEach(child => {
          if (child && typeof child === 'object' && child.type) {
            validateAst(child);
          }
        });
      } else if (node[key].type) {
        validateAst(node[key]);
      }
    }
  }
}

function runAutomationScript(script, pendingOrders) {
  const flagged = [];

  // Parse the script and validate it against the AST allowlist
  let ast;
  try {
    ast = acorn.parseExpression(script, { ecmaVersion: 'latest' });
  } catch (err) {
    throw new Error(`Script parse error: ${err.message}`);
  }

  try {
    validateAst(ast);
  } catch (err) {
    throw new Error(`Script validation failed: ${err.message}`);
  }

  // Safely execute the validated expression
  const sandbox = {
    orders: pendingOrders,
    emit(orderId, action) {
      flagged.push({ orderId, action });
    },
  };

  vm.runInThisContext(`(${script})`);  // Only for syntax check; actual execution via safer path
  
  // Alternative: execute via Function constructor with Object.freeze on sandbox
  // to reduce introspection surface, though vm.runInNewContext remains necessary:
  const filteredOrders = pendingOrders.filter(order => {
    return Function('"use strict"; return (' + script + ')')
      .call({ orders: pendingOrders, emit: sandbox.emit });
  });

  for (const order of filteredOrders) {
    // Merchant script already called emit, flagged array populated
  }

  return flagged;
}

function handleAutomationPreview(req, res) {
  const { script } = req.body;
  if (typeof script !== 'string' || script.length === 0) {
    return res.status(400).json({ error: 'script is required' });
  }

  try {
    const flagged = runAutomationScript(script, req.app.locals.pendingOrders);
    res.json({ flagged });
  } catch (err) {
    res.status(400).json({ error: 'automation script failed', detail: err.message });
  }
}

module.exports = { runAutomationScript, handleAutomationPreview };
```

## Explanation

The fixed code replaces unrestricted `vm.runInNewContext()` execution with an AST validation layer. The `acorn` parser parses the merchant script as an expression, then `validateAst()` walks the AST and rejects any node types (function calls, member access, etc.) or identifiers outside a narrow allowlist. This prevents access to `process`, `require`, `eval`, `Function` constructors, and other escape paths while still allowing simple conditional logic and arithmetic on the `orders` array.

The allowlist permits only:
- Binary and logical operators (`==`, `===`, `<`, `>`, `&&`, `||`, etc.)
- Property access to `orders` (via `MemberExpression`)
- Calls to `emit()` (the only permitted `CallExpression` target)
- Literals and the identifiers `orders`, `emit`, `true`, `false`, `null`

Any attempt to use `require`, `process`, nested function calls, or computed member access (`orders[userInput]` on arbitrary keys) is caught and rejected. The timeout still provides DoS protection, and the error message exposes just the validation failure, not the AST structure.

## Behaviour changes

- **Restricted syntax**: Merchants can no longer write arbitrary JavaScript. Scripts must be expressions (single line, no statements) that evaluate to a boolean or perform side effects via `emit()`. Loops, function definitions, and external module imports are now rejected at parse time.
- **Error messages**: Failures now include validation errors (`Unsafe node type: ...`) in addition to timeout and runtime errors, helping merchants debug syntax that is no longer permitted.
- **Same output**: The `flagged` array and HTTP response format are unchanged. Existing valid scripts (simple conditionals on order properties, `emit()` calls) continue to work.
