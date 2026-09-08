## Verdict

Exploitable. CWE-94 (Improper Control of Generation of Code, `eval()` injection), confidence: high.

- Location: `QuickCalculationHandler.php`, line 26.
- Source: `$post['expr']`, the raw `expr` form field from `POST /admin/tools/quick-calc` (line 18).
- Sink: `eval('$result = ' . $expr . ';')` (line 26) - the attacker-controlled string is concatenated directly into a statement that is compiled and executed by the PHP engine.
- Data flow: `$expr` is read from the request with no validation, transformation, or encoding between the source and the sink, so any PHP the caller supplies (e.g. `1; system('id'); //`) runs with the full privileges of the request handler.

## Source

`$post['expr']` (line 18), sourced from the POST body of an admin-tool request. There is no length limit, character-set restriction, or expression-grammar check applied before it reaches `eval()`.

## Fix

### File: QuickCalculationHandler.php

```php
<?php
/**
 * Admin-only "quick calculation" tool. Lets an operator type an arithmetic
 * expression (e.g. "12 * (3 + 7)") and see the result without opening a
 * separate calculator. Targets PHP 8.1.
 */

require_once __DIR__ . '/SafeArithmeticEvaluator.php';

class QuickCalculationHandler
{
    /**
     * Handles POST /admin/tools/quick-calc.
     *
     * Expects a single form field, "expr", containing a plain arithmetic
     * expression such as "45 * 1.15" or "(10 + 2) / 4". Only numeric
     * literals, +, -, *, /, and parentheses are accepted.
     */
    public function handleRequest(array $post): array
    {
        $expr = $post['expr'] ?? '';

        if ($expr === '') {
            return ['ok' => false, 'error' => 'Enter an expression to evaluate.'];
        }

        try {
            $result = SafeArithmeticEvaluator::evaluate($expr);
        } catch (InvalidArgumentException $e) {
            return ['ok' => false, 'error' => 'Enter a valid arithmetic expression.'];
        }

        return ['ok' => true, 'result' => $result];
    }
}
```

### File: SafeArithmeticEvaluator.php

```php
<?php
/**
 * Evaluates a plain arithmetic expression (+, -, *, /, parentheses, and
 * numeric literals only) without executing any PHP code. This replaces
 * eval() as the sink for CWE-94: the grammar below has no way to name a
 * function, a variable, or a class, so there is nothing for injected text
 * to invoke.
 */
final class SafeArithmeticEvaluator
{
    /** @var string */
    private $expr;

    /** @var int */
    private $pos;

    /** @var int */
    private $length;

    private function __construct(string $expr)
    {
        $this->expr = $expr;
        $this->pos = 0;
        $this->length = strlen($expr);
    }

    /**
     * @return int|float
     */
    public static function evaluate(string $expr)
    {
        $parser = new self($expr);
        $result = $parser->parseExpression();
        $parser->skipWhitespace();

        if ($parser->pos !== $parser->length) {
            throw new InvalidArgumentException('unexpected character at position ' . $parser->pos);
        }

        return $result;
    }

    /** @return int|float */
    private function parseExpression()
    {
        $value = $this->parseTerm();

        while (true) {
            $this->skipWhitespace();
            $op = $this->peekChar();

            if ($op === '+' || $op === '-') {
                $this->pos++;
                $rhs = $this->parseTerm();
                $value = ($op === '+') ? $value + $rhs : $value - $rhs;
                continue;
            }

            break;
        }

        return $value;
    }

    /** @return int|float */
    private function parseTerm()
    {
        $value = $this->parseFactor();

        while (true) {
            $this->skipWhitespace();
            $op = $this->peekChar();

            if ($op === '*' || $op === '/') {
                $this->pos++;
                $rhs = $this->parseFactor();

                if ($op === '*') {
                    $value = $value * $rhs;
                } else {
                    if ($rhs === 0 || $rhs === 0.0) {
                        throw new InvalidArgumentException('division by zero');
                    }
                    $value = $value / $rhs;
                }
                continue;
            }

            break;
        }

        return $value;
    }

    /** @return int|float */
    private function parseFactor()
    {
        $this->skipWhitespace();
        $ch = $this->peekChar();

        if ($ch === '+' || $ch === '-') {
            $this->pos++;
            $value = $this->parseFactor();
            return $ch === '-' ? -$value : $value;
        }

        if ($ch === '(') {
            $this->pos++;
            $value = $this->parseExpression();
            $this->skipWhitespace();

            if ($this->peekChar() !== ')') {
                throw new InvalidArgumentException('expected closing parenthesis');
            }

            $this->pos++;
            return $value;
        }

        return $this->parseNumber();
    }

    /** @return int|float */
    private function parseNumber()
    {
        $start = $this->pos;

        while ($this->pos < $this->length && ctype_digit($this->expr[$this->pos])) {
            $this->pos++;
        }

        if ($this->pos < $this->length && $this->expr[$this->pos] === '.') {
            $this->pos++;
            while ($this->pos < $this->length && ctype_digit($this->expr[$this->pos])) {
                $this->pos++;
            }
        }

        if ($this->pos === $start) {
            throw new InvalidArgumentException('expected a number at position ' . $this->pos);
        }

        $text = substr($this->expr, $start, $this->pos - $start);

        return strpos($text, '.') !== false ? (float) $text : (int) $text;
    }

    private function skipWhitespace(): void
    {
        while ($this->pos < $this->length && ctype_space($this->expr[$this->pos])) {
            $this->pos++;
        }
    }

    private function peekChar(): ?string
    {
        return $this->pos < $this->length ? $this->expr[$this->pos] : null;
    }
}
```

## Explanation

The vulnerability is that `eval()` compiles and runs whatever text follows `$result = `, so any PHP the caller appends after (or instead of) a legitimate expression executes with the process's full privileges. Per the PHP-specific guidance, there is no sanitization that makes `eval($userInput)` safe, so the fix removes the `eval()` call entirely rather than trying to filter its input. `SafeArithmeticEvaluator` is a small recursive-descent parser whose grammar recognizes only numeric literals, `+`, `-`, `*`, `/`, and parentheses; it has no production that can reference a variable, call a function, or name a class, so there is no injection surface left to sanitize - unrecognized input (any letter, semicolon, quote, `$`, etc.) fails to parse and is rejected. `QuickCalculationHandler` now calls this evaluator instead of `eval()` and catches `InvalidArgumentException` to turn a malformed or unsafe expression into the same `['ok' => false, ...]` shape the handler already uses for the empty-input case, rather than letting a parse failure propagate as an uncaught error.

## Behaviour changes

- **Division by zero and malformed input now return `['ok' => false, 'error' => ...]` instead of the previous crash.** Under the original `eval()` sink, an expression like `1/0` throws an uncaught `DivisionByZeroError` (PHP 8) and a syntactically invalid expression throws an uncaught `ParseError` - both would surface as an unhandled fatal error to the caller. The new code catches these cases inside `SafeArithmeticEvaluator` and returns the same structured error response the handler already produces for an empty `expr`. This is a direct consequence of closing the sink (a parser has to have some behavior for input outside its grammar) and does not affect any legitimate expression.
- **The error message no longer includes an eval-produced PHP diagnostic.** The original had no explicit invalid-input handling (it would crash rather than emit a message), so there is no prior message text to preserve; the new message is a generic, non-leaking `"Enter a valid arithmetic expression."` consistent with the file's existing user-facing error strings.
- **Numeric formatting/precision**: results are produced by native PHP `+ - * /` on `int`/`float` operands parsed from the literal text, the same arithmetic PHP would have performed inside the `eval()`'d statement, so results for valid expressions (e.g. `12 * (3 + 7)` -> `120`, `(10 + 2) / 4` -> `3`) are unchanged.
- No other arguments, return shape, or control flow changed. The success path still returns `['ok' => true, 'result' => $result]` with `$result` holding the computed numeric value.

## Verification

- `php -l` (PHP 8.5 CLI, locally available) on both files: `No syntax errors detected` for `QuickCalculationHandler.php` and `SafeArithmeticEvaluator.php`.
- Functional smoke test (`php test.php`) against the fixed handler, run from a scratch copy outside the repository:
  - `handleRequest(['expr' => '12 * (3 + 7)'])` -> `{"ok":true,"result":120}`
  - `handleRequest(['expr' => '45 * 1.15'])` -> `{"ok":true,"result":51.74999999999999}`
  - `handleRequest(['expr' => '(10 + 2) / 4'])` -> `{"ok":true,"result":3}`
  - `handleRequest(['expr' => '-5 + 3'])` -> `{"ok":true,"result":-2}`
  - `handleRequest(['expr' => ''])` -> `{"ok":false,"error":"Enter an expression to evaluate."}` (unchanged)
  - `handleRequest(['expr' => '1/0'])` -> `{"ok":false,"error":"Enter a valid arithmetic expression."}` (previously an uncaught `DivisionByZeroError`)
  - `handleRequest(['expr' => "1; system('id')"])` -> `{"ok":false,"error":"Enter a valid arithmetic expression."}` (previously arbitrary command execution)
  - `handleRequest(['expr' => "'a'.'b'"])` -> rejected
  - `handleRequest(['expr' => '$GLOBALS'])` -> rejected
  - `handleRequest(['expr' => 'abc'])` -> rejected
- Every symbol the fix introduces is either standard PHP library (`strlen`, `substr`, `strpos`, `ctype_digit`, `ctype_space`, `InvalidArgumentException`) or defined in `SafeArithmeticEvaluator.php` itself; none are assumed from an external package.

**Assumptions**: The case's arithmetic-expression feature (numbers, `+ - * /`, parentheses) is treated as the full intended grammar, matching both examples in the class's own doc comment (`"45 * 1.15"`, `"(10 + 2) / 4"`); no exponentiation, modulo, or function calls (e.g. `sqrt`) were inferred as in-scope since neither the code nor its comments reference them.
