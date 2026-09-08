## Verdict

Confirmed. `formulaEngine.js` builds a `new Function('order', \`return (${expression});\`)` from `expression`, and `formulaController.js` passes `req.body.expression` straight into it with no validation or sandboxing. Any caller of the preview endpoint can submit arbitrary JavaScript (e.g. `require('child_process').execSync('...')` via `this.constructor.constructor(...)`, or simply referencing globals like `process`) and have it executed server-side. This is CWE-94, Improper Control of Generation of Code.

## Source

- Taint source: `req.body.expression` in `formulaController.js`.
- Data flow: `previewFormula(req, res)` reads `expression` from the request body and calls `evaluateFormula(expression, sampleOrder)`.
- Sink: `evaluateFormula` in `formulaEngine.js` interpolates `expression` directly into the body of a `new Function(...)` call and immediately invokes the resulting function, giving attacker-supplied text full JavaScript execution in the server process (including access to global objects and, via constructor-chain tricks, to `require`).

## Fix

### File: formulaEngine.js
```javascript
'use strict';

// Restricted arithmetic formula evaluator.
//
// Formulas may contain only: number literals, the operators + - * / %,
// parentheses, unary +/-, and dotted property paths rooted at `order`
// (e.g. `order.total`). There is no code generation, function-call syntax,
// or access to anything outside the `order` object, so a formula string
// cannot execute arbitrary logic no matter what a caller submits.

const TOKEN_REGEX = /([0-9]+(?:\.[0-9]+)?)|([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)|([+\-*/%()])/y;

function tokenize(expression) {
  const tokens = [];
  const len = expression.length;
  let pos = 0;

  while (pos < len) {
    const ch = expression[pos];
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      pos += 1;
      continue;
    }

    TOKEN_REGEX.lastIndex = pos;
    const match = TOKEN_REGEX.exec(expression);
    if (!match || match.index !== pos) {
      throw new Error(`Unexpected character in formula at position ${pos}`);
    }

    if (match[1] !== undefined) {
      tokens.push({ type: 'number', value: parseFloat(match[1]) });
    } else if (match[2] !== undefined) {
      tokens.push({ type: 'identifier', value: match[2] });
    } else {
      tokens.push({ type: 'op', value: match[3] });
    }

    pos = TOKEN_REGEX.lastIndex;
  }

  return tokens;
}

function resolveIdentifier(path, order) {
  const parts = path.split('.');
  if (parts[0] !== 'order') {
    throw new Error(`Unknown identifier "${path}" in formula`);
  }

  let value = order;
  for (let i = 1; i < parts.length; i += 1) {
    const key = parts[i];
    if (
      value === null ||
      typeof value !== 'object' ||
      key === '__proto__' ||
      key === 'prototype' ||
      key === 'constructor' ||
      !Object.prototype.hasOwnProperty.call(value, key)
    ) {
      throw new Error(`Unknown identifier "${path}" in formula`);
    }
    value = value[key];
  }

  if (typeof value !== 'number' || Number.isNaN(value)) {
    throw new Error(`Identifier "${path}" is not a number`);
  }
  return value;
}

function createParser(tokens, order) {
  let index = 0;

  const peek = () => tokens[index];
  const advance = () => tokens[index++];

  function expectOp(op) {
    const token = advance();
    if (!token || token.type !== 'op' || token.value !== op) {
      throw new Error(`Expected "${op}" in formula`);
    }
  }

  function parsePrimary() {
    const token = peek();
    if (!token) {
      throw new Error('Unexpected end of formula');
    }
    if (token.type === 'number') {
      advance();
      return token.value;
    }
    if (token.type === 'identifier') {
      advance();
      return resolveIdentifier(token.value, order);
    }
    if (token.type === 'op' && token.value === '(') {
      advance();
      const value = parseExpression();
      expectOp(')');
      return value;
    }
    throw new Error('Unexpected token in formula');
  }

  function parseUnary() {
    const token = peek();
    if (token && token.type === 'op' && (token.value === '+' || token.value === '-')) {
      advance();
      const value = parseUnary();
      return token.value === '-' ? -value : value;
    }
    return parsePrimary();
  }

  function parseTerm() {
    let value = parseUnary();
    let token = peek();
    while (token && token.type === 'op' && (token.value === '*' || token.value === '/' || token.value === '%')) {
      advance();
      const rhs = parseUnary();
      if (token.value === '*') value *= rhs;
      else if (token.value === '/') value /= rhs;
      else value %= rhs;
      token = peek();
    }
    return value;
  }

  function parseExpression() {
    let value = parseTerm();
    let token = peek();
    while (token && token.type === 'op' && (token.value === '+' || token.value === '-')) {
      advance();
      const rhs = parseTerm();
      value = token.value === '+' ? value + rhs : value - rhs;
      token = peek();
    }
    return value;
  }

  return {
    parse() {
      const value = parseExpression();
      if (index !== tokens.length) {
        throw new Error('Unexpected trailing tokens in formula');
      }
      return value;
    },
  };
}

function evaluateFormula(expression, order) {
  if (typeof expression !== 'string') {
    throw new Error('Formula must be a string');
  }
  const tokens = tokenize(expression);
  return createParser(tokens, order).parse();
}

module.exports = { evaluateFormula };
```

## Explanation

The original sink built a JavaScript function body by string interpolation and executed it with `new Function`, which is exactly as dangerous as `eval`: whatever text `expression` contains becomes code that runs with the privileges of the server process, and because `expression` originates from `req.body`, any client controls that code.

The fix removes code generation entirely. `evaluateFormula` now runs a small hand-written recursive-descent parser over a fixed grammar: numeric literals, the operators `+ - * / %`, parentheses, unary sign, and dotted identifiers. The only identifier root the grammar accepts is `order`, and property access walks the `order` object one segment at a time using `Object.prototype.hasOwnProperty.call`, explicitly rejecting `__proto__`, `prototype`, and `constructor` so a formula cannot climb the prototype chain. Every resolved value is required to be a finite `number`, so even a successful property lookup can't smuggle in a function, object, or string to manipulate further. There is no `eval`, `Function`, or dynamic `import`/`require` anywhere in the evaluator, so no sequence of characters in `expression` can cause anything other than arithmetic on `order`'s own numeric fields - the parser has no syntax for calling anything, and unrecognized tokens (including things like `;`, backticks, or `=>`) raise an error instead of being executed. `formulaController.js` needs no change: it already only forwards `expression` and a plain data object as `order`.
