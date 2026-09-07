## Verdict
exploitable

## Source
User-supplied arithmetic expression from HTTP POST parameter `$post['expr']` at line 18, passed to the dangerous sink without validation.

## Fix

### File: QuickCalculationHandler.php
```php
<?php
/**
 * Admin-only "quick calculation" tool. Lets an operator type an arithmetic
 * expression (e.g. "12 * (3 + 7)") and see the result without opening a
 * separate calculator. Targets PHP 8.1.
 */

class QuickCalculationHandler
{
    /**
     * Handles POST /admin/tools/quick-calc.
     *
     * Expects a single form field, "expr", containing a PHP-syntax
     * arithmetic expression such as "45 * 1.15" or "(10 + 2) / 4".
     */
    public function handleRequest(array $post): array
    {
        $expr = $post['expr'] ?? '';

        if ($expr === '') {
            return ['ok' => false, 'error' => 'Enter an expression to evaluate.'];
        }

        try {
            $result = $this->evaluateExpression($expr);
            return ['ok' => true, 'result' => $result];
        } catch (\Exception $e) {
            return ['ok' => false, 'error' => 'Invalid expression'];
        }
    }

    private function evaluateExpression(string $expr): float|int
    {
        // Strict allowlist validation: only digits, operators, parentheses, and whitespace
        if (!preg_match('/^[\d\+\-\*\/\%\(\)\.\s]+$/', $expr)) {
            throw new \InvalidArgumentException('Invalid characters in expression');
        }

        // Remove whitespace for parsing
        $expr = preg_replace('/\s+/', '', $expr);

        // Validate balanced parentheses
        if (substr_count($expr, '(') !== substr_count($expr, ')')) {
            throw new \InvalidArgumentException('Unbalanced parentheses');
        }

        // Tokenize and parse the expression safely
        $tokens = $this->tokenize($expr);
        $evaluator = new MathExpressionEvaluator($tokens);
        return $evaluator->evaluate();
    }

    private function tokenize(string $expr): array
    {
        $tokens = [];
        $number = '';

        for ($i = 0; $i < strlen($expr); $i++) {
            $char = $expr[$i];

            if (ctype_digit($char) || $char === '.') {
                $number .= $char;
            } else {
                if ($number !== '') {
                    $tokens[] = (float)$number;
                    $number = '';
                }
                $tokens[] = $char;
            }
        }

        if ($number !== '') {
            $tokens[] = (float)$number;
        }

        return $tokens;
    }
}

class MathExpressionEvaluator
{
    private array $tokens;
    private int $pos = 0;

    public function __construct(array $tokens)
    {
        $this->tokens = $tokens;
    }

    public function evaluate(): float|int
    {
        $result = $this->parseAddition();
        if ($this->pos !== count($this->tokens)) {
            throw new \InvalidArgumentException('Unexpected tokens at end of expression');
        }
        return $result;
    }

    private function parseAddition(): float|int
    {
        $result = $this->parseMultiplication();

        while ($this->pos < count($this->tokens)) {
            $token = $this->tokens[$this->pos];

            if ($token === '+') {
                $this->pos++;
                $result += $this->parseMultiplication();
            } elseif ($token === '-') {
                $this->pos++;
                $result -= $this->parseMultiplication();
            } else {
                break;
            }
        }

        return $result;
    }

    private function parseMultiplication(): float|int
    {
        $result = $this->parsePrimary();

        while ($this->pos < count($this->tokens)) {
            $token = $this->tokens[$this->pos];

            if ($token === '*') {
                $this->pos++;
                $result *= $this->parsePrimary();
            } elseif ($token === '/') {
                $this->pos++;
                $divisor = $this->parsePrimary();
                if ($divisor == 0) {
                    throw new \InvalidArgumentException('Division by zero');
                }
                $result /= $divisor;
            } elseif ($token === '%') {
                $this->pos++;
                $result = fmod($result, $this->parsePrimary());
            } else {
                break;
            }
        }

        return $result;
    }

    private function parsePrimary(): float|int
    {
        if ($this->pos >= count($this->tokens)) {
            throw new \InvalidArgumentException('Unexpected end of expression');
        }

        $token = $this->tokens[$this->pos];

        if (is_numeric($token)) {
            $this->pos++;
            return $token;
        } elseif ($token === '(') {
            $this->pos++;
            $result = $this->parseAddition();

            if ($this->pos >= count($this->tokens) || $this->tokens[$this->pos] !== ')') {
                throw new \InvalidArgumentException('Missing closing parenthesis');
            }

            $this->pos++;
            return $result;
        } elseif ($token === '-') {
            $this->pos++;
            return -$this->parsePrimary();
        } elseif ($token === '+') {
            $this->pos++;
            return $this->parsePrimary();
        } else {
            throw new \InvalidArgumentException('Invalid token');
        }
    }
}
```

## Explanation
The original code used `eval('$result = ' . $expr . ';');` to evaluate arbitrary PHP expressions, which is exploitable: an attacker controlling the `$expr` parameter can inject arbitrary PHP code and execute it with full server access. There is no safe way to sandbox `eval()` in PHP. The fix replaces the dangerous `eval()` call with a safe recursive descent parser that:

1. Validates input strictly with a regex allowlist restricting characters to digits, arithmetic operators (`+`, `-`, `*`, `/`, `%`), parentheses, and whitespace, rejecting anything else immediately
2. Checks for balanced parentheses to prevent malformed syntax
3. Tokenizes the expression by splitting numbers and operators
4. Parses and evaluates the expression using a `MathExpressionEvaluator` class with proper operator precedence (multiplication/division before addition/subtraction), handling unary minus, and respecting parentheses without invoking any dynamic code execution

This eliminates the code injection vector entirely; user input is no longer passed to any function that interprets it as PHP source code.

## Behaviour changes
- **Input validation**: The fixed code rejects expressions containing any character outside the allowed set `[0-9+\-*/%().\s]`, where the original accepted any PHP expression. Invalid expressions now return an error message instead of attempting execution.
- **Error handling**: Malformed expressions (unbalanced parentheses, unexpected tokens, division by zero) now raise catchable exceptions that return an HTTP-level error response with a generic message. The original would either crash or potentially expose stack traces.
- **Operator precedence**: The parser explicitly enforces standard arithmetic precedence (multiplication and division before addition and subtraction). The original `eval()` followed PHP's operator precedence, which is identical for these operators, so the results are equivalent for valid expressions.
- **Floating-point handling**: The tokenizer stores numbers as floats and the evaluator performs floating-point arithmetic. The original `eval()` would preserve PHP's type juggling; for the stated use case (arithmetic expressions like "45 * 1.15") this is semantically equivalent.

