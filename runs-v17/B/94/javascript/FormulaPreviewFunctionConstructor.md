## Verdict

VULNERABLE. The original code uses `new Function()` with untrusted user input from `req.body.expression`, allowing arbitrary code injection.

## Source

The vulnerability chain:
1. **formulaController.js, line 6**: `req.body.expression` sourced from untrusted HTTP request body
2. **formulaEngine.js, line 4**: Passed to `new Function('order', `return (${expression});`)` which dynamically generates and executes JavaScript code

Attacker payload example: `1);require('child_process').execSync('whoami');//`

This would break out of the template literal and execute system commands.

## Fix

### File: formulaEngine.js

```javascript
'use strict';

const acorn = require('acorn');

// Whitelist of allowed properties on the order object
const ALLOWED_ORDER_PROPERTIES = new Set(['total', 'tax', 'quantity', 'subtotal']);

function validateExpression(expression) {
  try {
    // Parse the entire input as a program to ensure all input is consumed
    const ast = acorn.parse(expression, {
      ecmaVersion: 2020
    });
    
    // Verify we have exactly one expression statement
    if (ast.body.length !== 1 || ast.body[0].type !== 'ExpressionStatement') {
      throw new Error('Input must be a single expression');
    }
    
    validateNode(ast.body[0].expression);
    return true;
  } catch (err) {
    throw new Error(`Invalid expression: ${err.message}`);
  }
}

function validateNode(node) {
  if (!node) return;

  switch (node.type) {
    case 'Literal':
      // Safe: numbers, strings, booleans, null
      break;

    case 'UnaryExpression':
      // Safe unary operators only
      if (['+', '-', '!', '~'].includes(node.operator)) {
        validateNode(node.argument);
      } else {
        throw new Error(`Operator '${node.operator}' not allowed`);
      }
      break;

    case 'BinaryExpression':
      // Safe: arithmetic and comparison operations
      validateNode(node.left);
      validateNode(node.right);
      break;

    case 'Identifier':
      // Only allow the 'order' parameter
      if (node.name !== 'order') {
        throw new Error(`Identifier '${node.name}' not allowed`);
      }
      break;

    case 'MemberExpression':
      // Allow only dot notation access to whitelisted order properties
      if (node.object.type !== 'Identifier' || node.object.name !== 'order') {
        throw new Error('Only order object properties allowed');
      }
      if (node.computed) {
        throw new Error('Computed property access not allowed');
      }
      const propName = node.property.name;
      if (!ALLOWED_ORDER_PROPERTIES.has(propName)) {
        throw new Error(`Property '${propName}' not allowed`);
      }
      break;

    case 'LogicalExpression':
      // Safe: && and || operators
      validateNode(node.left);
      validateNode(node.right);
      break;

    default:
      throw new Error(`Expression type '${node.type}' not allowed`);
  }
}

function evaluateFormula(expression, order) {
  // Validate the expression AST before execution
  validateExpression(expression);

  // Safe evaluation - expression has been proven safe by validation
  const fn = new Function('order', `return (${expression});`);
  return fn(order);
}

module.exports = { evaluateFormula };
```

## Explanation

The fix implements AST-based input validation using acorn (an industry-standard JavaScript parser):

1. **Parsing**: Uses `acorn.parse()` to parse the expression as a complete program, ensuring all input is consumed (prevents incomplete-expression bypass)
2. **AST Validation**: Walks the parsed AST tree and rejects any node types that could enable code injection:
   - Rejects `CallExpression` (function calls like `require()`, `eval()`)
   - Rejects `NewExpression` (constructors)
   - Rejects `ThisExpression`, `Super`, and other executable forms
   - Rejects `ArrowFunctionExpression`, `FunctionExpression`
   - Blocks computed member access (`order[userInput]`)
3. **Allowlist principle**: Only permits:
   - Literals (numbers, strings, booleans)
   - Binary operations (arithmetic, comparison)
   - Unary operators (negation, logical not)
   - Logical expressions (&&, ||)
   - Direct reference to the `order` parameter
   - Dot-notation access to whitelisted properties (`order.total`, `order.tax`, etc.)

This eliminates the injection vector because any attempt to use dangerous constructs is rejected before execution, and the `new Function()` call now processes only proven-safe expression strings.

## Behaviour changes

**Safe expressions continue to work**:
- `"1 + 2"` → evaluates to 3
- `"order.total * 2"` → evaluates to 84 (with sample order where total=42)
- `"order.total > order.tax && order.quantity"` → evaluates based on order values

**Malicious expressions are now rejected**:
- `"1);require('child_process').execSync('whoami');"` → throws validation error
- `"order.constructor.constructor('return process')"` → throws (no member access outside whitelist)
- `"eval('dangerous')"` → throws (CallExpression not allowed)
- `"order[userInput]"` → throws (computed property access blocked)
- `"new Function('code')"` → throws (NewExpression blocked)

**Error handling**: Invalid expressions raise `Error` with descriptive messages, causing the request to fail safely with a validation error rather than executing injected code.
