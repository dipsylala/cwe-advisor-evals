## Verdict

Confirmed. `evaluateExpression` passes `req.body.expression`, an attacker-controlled HTTP request body field, directly into `eval()` after simple string concatenation. Any JavaScript the caller supplies (not just arithmetic) runs with the privileges of the Node process — e.g. `require('child_process').execSync('...')` or reading/writing files via `require('fs')` — giving full remote code execution, not merely an unexpected calculation result.

## Source

`req.body.expression` in `evaluateExpression` (`calculatorController.js:6`), an untrusted value taken verbatim from the POST body of `/api/calculator/evaluate`, flows unmodified (only wrapped in parentheses) into the sink at line 15.

## Fix

### File: calculatorController.js
```javascript
'use strict';

// Express handler for POST /api/calculator/evaluate
// Body: { expression: "12 * (3 + 4)" }
function evaluateExpression(req, res) {
  const expression = req.body.expression;

  if (typeof expression !== 'string' || expression.length === 0) {
    return res.status(400).json({ error: 'expression is required' });
  }

  // Reject anything but digits, decimal points, arithmetic operators,
  // parentheses, and whitespace before attempting to parse. This blocks
  // identifiers, brackets, quotes, semicolons, etc. so the parser below
  // only ever sees a candidate arithmetic expression.
  if (!/^[0-9+\-*/%.()\s]+$/.test(expression)) {
    return res.status(400).json({ error: 'expression contains unsupported characters' });
  }

  let result;
  try {
    result = evaluateArithmetic(expression);
  } catch (err) {
    return res.status(400).json({ error: 'invalid expression' });
  }

  res.json({ result });
}

// Minimal recursive-descent evaluator for arithmetic expressions.
// Grammar:
//   expr   := term (('+' | '-') term)*
//   term   := factor (('*' | '/' | '%') factor)*
//   factor := ('+' | '-') factor | number | '(' expr ')'
// No identifiers, member access, or function calls are ever recognized,
// so there is no way for input to reach code execution, unlike eval().
function evaluateArithmetic(source) {
  const tokens = tokenize(source);
  let pos = 0;

  function peek() {
    return tokens[pos];
  }

  function consume() {
    return tokens[pos++];
  }

  function parseExpr() {
    let value = parseTerm();
    while (peek() === '+' || peek() === '-') {
      const op = consume();
      const rhs = parseTerm();
      value = op === '+' ? value + rhs : value - rhs;
    }
    return value;
  }

  function parseTerm() {
    let value = parseFactor();
    while (peek() === '*' || peek() === '/' || peek() === '%') {
      const op = consume();
      const rhs = parseFactor();
      if ((op === '/' || op === '%') && rhs === 0) {
        throw new Error('division by zero');
      }
      value = op === '*' ? value * rhs : op === '/' ? value / rhs : value % rhs;
    }
    return value;
  }

  function parseFactor() {
    const tok = peek();
    if (tok === '+' || tok === '-') {
      consume();
      const value = parseFactor();
      return tok === '-' ? -value : value;
    }
    if (tok === '(') {
      consume();
      const value = parseExpr();
      if (consume() !== ')') {
        throw new Error('expected closing parenthesis');
      }
      return value;
    }
    if (typeof tok === 'number') {
      consume();
      return tok;
    }
    throw new Error('unexpected token');
  }

  const result = parseExpr();
  if (pos !== tokens.length) {
    throw new Error('unexpected trailing input');
  }
  if (!Number.isFinite(result)) {
    throw new Error('non-finite result');
  }
  return result;
}

function tokenize(source) {
  const tokens = [];
  const re = /\s*(\d+(?:\.\d+)?|[+\-*/%()])/y;
  let index = 0;
  while (index < source.length) {
    if (/\s/.test(source[index])) {
      index++;
      continue;
    }
    re.lastIndex = index;
    const match = re.exec(source);
    if (!match || match.index !== index) {
      throw new Error('unexpected character');
    }
    const value = match[1];
    tokens.push(/^[0-9.]/.test(value) ? Number(value) : value);
    index = re.lastIndex;
  }
  return tokens;
}

module.exports = { evaluateExpression };
```

## Explanation

The original handler builds the string `'(' + expression + ')'` and hands it to `eval()`, so `eval` executes whatever JavaScript arrives in the request body rather than only arithmetic — the parentheses wrapper does not constrain what the string can contain. The fix removes `eval()` (and avoids `new Function()`, which is an equivalent sink) entirely and replaces it with a purpose-built arithmetic evaluator: a tokenizer that only ever emits numbers and the operators `+ - * / % ( )`, and a recursive-descent parser built on that fixed grammar. Because the parser has no production for identifiers, member access, or calls, there is no code path from attacker-controlled text to code execution, no matter what the string contains.

An additional allowlist regex (`^[0-9+\-*/%.()\s]+$`) is applied first as defense in depth so obviously invalid input (letters, quotes, semicolons, brackets) is rejected with a clear 400 before parsing is attempted; it does not replace the parser as the actual safety boundary, since the parser alone is already immune to injection — the regex only narrows what has to be shown to the parser and gives a more direct error for garbage input. Division and modulo by zero and non-finite results are rejected explicitly so malformed input fails predictably as a 400 rather than surfacing `Infinity`/`NaN`. `12 * (3 + 4)` still evaluates to `84` as before; an input such as `require('child_process').execSync('id')` is now rejected at the character-allowlist check before it ever reaches the evaluator.
