## Verdict

Confirmed. `handleRequest()` takes the `expr` field straight from the POST body (`$post['expr']`) and concatenates it, unmodified, into a string passed to `eval()`. Any PHP statement the attacker types is executed with the privileges of the request handler - this is not limited to arithmetic despite the docblock's intent, since `eval()` runs arbitrary PHP, not just expressions.

## Source

`$expr = $post['expr'] ?? '';` on line 18 - attacker-controlled form field from `POST /admin/tools/quick-calc`, flowing unsanitized into the `eval('$result = ' . $expr . ';')` sink on line 26.

## Fix

Removed `eval()` entirely and replaced it with a small self-contained recursive-descent evaluator that only understands numbers, `+ - * /`, unary sign, and parentheses. The input is tokenized against a strict character set first (reject anything else outright), so there is no code path back to PHP execution - the parser can only ever produce arithmetic, never statements, function calls, or variable access.

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
     * Expects a single form field, "expr", containing an arithmetic
     * expression such as "45 * 1.15" or "(10 + 2) / 4". Only numbers,
     * +, -, *, /, and parentheses are accepted - the expression is
     * parsed and evaluated directly, never passed to eval().
     */
    public function handleRequest(array $post): array
    {
        $expr = $post['expr'] ?? '';

        if ($expr === '') {
            return ['ok' => false, 'error' => 'Enter an expression to evaluate.'];
        }

        try {
            $result = SafeArithmeticEvaluator::evaluate($expr);
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => 'Invalid expression: ' . $e->getMessage()];
        }

        return ['ok' => true, 'result' => $result];
    }
}
```

### File: SafeArithmeticEvaluator.php
```php
<?php
/**
 * Evaluates a plain arithmetic expression (numbers, + - * /, parentheses,
 * unary sign) without ever invoking eval() or any other code-execution
 * primitive. The input is tokenized against a strict character allowlist
 * and then parsed with a small recursive-descent grammar, so the only
 * possible outputs are numeric - there is no path from input text to
 * PHP statement execution.
 */
class SafeArithmeticEvaluator
{
    /** @var array<int, string> */
    private array $tokens;
    private int $pos = 0;

    public static function evaluate(string $expr): float
    {
        $evaluator = new self($expr);
        $value = $evaluator->parseExpression();

        if ($evaluator->pos !== count($evaluator->tokens)) {
            throw new \InvalidArgumentException('unexpected trailing input');
        }

        return $value;
    }

    private function __construct(string $expr)
    {
        if (strlen($expr) > 200) {
            throw new \InvalidArgumentException('expression too long');
        }

        if (!preg_match('/^[0-9+\-*\/().\s]*$/', $expr)) {
            throw new \InvalidArgumentException('only digits, + - * / ( ) and . are allowed');
        }

        $this->tokens = $this->tokenize($expr);

        if ($this->tokens === []) {
            throw new \InvalidArgumentException('empty expression');
        }
    }

    /** @return array<int, string> */
    private function tokenize(string $expr): array
    {
        $tokens = [];
        $length = strlen($expr);
        $i = 0;

        while ($i < $length) {
            $ch = $expr[$i];

            if (ctype_space($ch)) {
                $i++;
                continue;
            }

            if (in_array($ch, ['+', '-', '*', '/', '(', ')'], true)) {
                $tokens[] = $ch;
                $i++;
                continue;
            }

            if (ctype_digit($ch) || $ch === '.') {
                $start = $i;
                $seenDot = false;

                while ($i < $length && (ctype_digit($expr[$i]) || $expr[$i] === '.')) {
                    if ($expr[$i] === '.') {
                        if ($seenDot) {
                            throw new \InvalidArgumentException('malformed number');
                        }
                        $seenDot = true;
                    }
                    $i++;
                }

                $numberText = substr($expr, $start, $i - $start);
                if ($numberText === '.' || $numberText === '') {
                    throw new \InvalidArgumentException('malformed number');
                }

                $tokens[] = $numberText;
                continue;
            }

            throw new \InvalidArgumentException('unexpected character');
        }

        return $tokens;
    }

    private function peek(): ?string
    {
        return $this->tokens[$this->pos] ?? null;
    }

    private function advance(): string
    {
        return $this->tokens[$this->pos++];
    }

    // expression := term (('+' | '-') term)*
    private function parseExpression(): float
    {
        $value = $this->parseTerm();

        while (($op = $this->peek()) === '+' || $op === '-') {
            $this->advance();
            $right = $this->parseTerm();
            $value = $op === '+' ? $value + $right : $value - $right;
        }

        return $value;
    }

    // term := factor (('*' | '/') factor)*
    private function parseTerm(): float
    {
        $value = $this->parseFactor();

        while (($op = $this->peek()) === '*' || $op === '/') {
            $this->advance();
            $right = $this->parseFactor();

            if ($op === '/') {
                if ($right == 0.0) {
                    throw new \InvalidArgumentException('division by zero');
                }
                $value = $value / $right;
            } else {
                $value = $value * $right;
            }
        }

        return $value;
    }

    // factor := number | '(' expression ')' | ('+' | '-') factor
    private function parseFactor(): float
    {
        $token = $this->peek();

        if ($token === null) {
            throw new \InvalidArgumentException('unexpected end of expression');
        }

        if ($token === '+' || $token === '-') {
            $this->advance();
            $value = $this->parseFactor();
            return $token === '-' ? -$value : $value;
        }

        if ($token === '(') {
            $this->advance();
            $value = $this->parseExpression();

            if ($this->peek() !== ')') {
                throw new \InvalidArgumentException('missing closing parenthesis');
            }
            $this->advance();

            return $value;
        }

        if (is_numeric($token)) {
            $this->advance();
            return (float) $token;
        }

        throw new \InvalidArgumentException('unexpected token');
    }
}
```

## Explanation

`eval()` executes any PHP source it is given, not just arithmetic - the code comment describing the field as "a PHP-syntax arithmetic expression" does not constrain what the interpreter will accept, so a request body such as `expr=system('id')` or `expr=1; file_put_contents(...)` runs with the full privileges of the handler. There is no safe way to sandbox `eval()` itself in PHP; the only reliable fix is to never hand attacker-controlled text to it.

The replacement evaluator closes the sink structurally rather than by filtering: input is first checked against an allowlist of the characters a numeric expression can legitimately contain (digits, `.`, `+ - * /`, parentheses, whitespace), then tokenized and parsed with a grammar that can only produce arithmetic operations on numbers. There is no branch in the parser that reaches a function call, variable reference, or any other PHP construct, so even a maximally crafted input cannot escape into code execution - it can only fail to parse or evaluate to a number. Division by zero and malformed numbers are caught explicitly and surfaced as ordinary validation errors, matching the existing `['ok' => false, 'error' => ...]` response shape the handler already uses for a blank expression.
