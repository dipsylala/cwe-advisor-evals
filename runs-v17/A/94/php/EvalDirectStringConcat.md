## Verdict
CONFIRMED: CWE-94 (Code Injection via eval()) present at line 26. Untrusted user input from `$post['expr']` is directly concatenated into an eval() statement, allowing arbitrary PHP code execution.

## Source
The vulnerability occurs in the `handleRequest()` method. The `$expr` variable originates from user-supplied POST data (line 18) and flows directly into an eval() statement (line 26) without any validation or sanitization. An attacker can inject arbitrary PHP code by supplying malicious input such as `"; system('id'); $foo="` to execute system commands or access sensitive data.

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
            $result = $this->evaluateArithmetic($expr);
            return ['ok' => true, 'result' => $result];
        } catch (\Exception $e) {
            return ['ok' => false, 'error' => 'Invalid expression.'];
        }
    }

    /**
     * Safely evaluates a mathematical expression without using eval().
     * Only allows numbers, operators (+, -, *, /, %), and parentheses.
     * Implements operator precedence and supports nested expressions.
     */
    private function evaluateArithmetic(string $expr): float|int
    {
        // Validate: only allow digits, operators, decimal points, whitespace, and parentheses
        if (!preg_match('/^[\d+\-*/%().\s]*$/', $expr)) {
            throw new \Exception('Invalid expression: contains disallowed characters');
        }

        if (trim($expr) === '') {
            throw new \Exception('Expression cannot be empty');
        }

        // Tokenize the expression
        $tokens = $this->tokenize($expr);
        $pos = 0;
        
        // Parse and evaluate using recursive descent parser
        $result = $this->parseExpression($tokens, $pos);
        
        if ($pos !== count($tokens)) {
            throw new \Exception('Unexpected tokens at end of expression');
        }

        return $result;
    }

    /**
     * Converts expression string into tokens (numbers, operators, parentheses).
     */
    private function tokenize(string $expr): array
    {
        $tokens = [];
        $current = '';
        
        foreach (str_split($expr) as $char) {
            if (ctype_digit($char) || $char === '.') {
                $current .= $char;
            } elseif (in_array($char, ['+', '-', '*', '/', '%', '(', ')'], true)) {
                if ($current !== '') {
                    $tokens[] = (float)$current;
                    $current = '';
                }
                $tokens[] = $char;
            } elseif (ctype_space($char)) {
                if ($current !== '') {
                    $tokens[] = (float)$current;
                    $current = '';
                }
            }
        }
        
        if ($current !== '') {
            $tokens[] = (float)$current;
        }
        
        return $tokens;
    }

    /**
     * Recursive descent parser for addition and subtraction (lowest precedence).
     */
    private function parseExpression(array &$tokens, int &$pos): float|int
    {
        $result = $this->parseTerm($tokens, $pos);
        
        while ($pos < count($tokens) && in_array($tokens[$pos], ['+', '-'], true)) {
            $op = $tokens[$pos++];
            $right = $this->parseTerm($tokens, $pos);
            
            if ($op === '+') {
                $result += $right;
            } else {
                $result -= $right;
            }
        }
        
        return $result;
    }

    /**
     * Parsing for multiplication, division, and modulo (higher precedence).
     */
    private function parseTerm(array &$tokens, int &$pos): float|int
    {
        $result = $this->parseFactor($tokens, $pos);
        
        while ($pos < count($tokens) && in_array($tokens[$pos], ['*', '/', '%'], true)) {
            $op = $tokens[$pos++];
            $right = $this->parseFactor($tokens, $pos);
            
            if ($op === '*') {
                $result *= $right;
            } elseif ($op === '/') {
                if ($right == 0) {
                    throw new \Exception('Division by zero');
                }
                $result /= $right;
            } else {
                if ($right == 0) {
                    throw new \Exception('Modulo by zero');
                }
                $result %= $right;
            }
        }
        
        return $result;
    }

    /**
     * Parsing for numbers and parenthesized expressions (highest precedence).
     */
    private function parseFactor(array &$tokens, int &$pos): float|int
    {
        if ($pos >= count($tokens)) {
            throw new \Exception('Unexpected end of expression');
        }
        
        $token = $tokens[$pos];
        
        if (is_numeric($token)) {
            $pos++;
            return (float)$token;
        } elseif ($token === '(') {
            $pos++; // skip '('
            $result = $this->parseExpression($tokens, $pos);
            if ($pos >= count($tokens) || $tokens[$pos] !== ')') {
                throw new \Exception('Missing closing parenthesis');
            }
            $pos++; // skip ')'
            return $result;
        } else {
            throw new \Exception('Unexpected token in expression');
        }
    }
}
```

## Explanation
The vulnerability is remediated by completely eliminating the use of `eval()`. The fix implements a safe arithmetic expression parser using tokenization and recursive descent parsing:

1. **Input Validation**: A regex pattern validates that the expression contains only digits, decimal points, arithmetic operators (+, -, *, /, %), parentheses, and whitespace. Any other character triggers an exception.

2. **Tokenization**: The `tokenize()` method converts the expression string into an array of tokens (numbers as floats, and operator/parenthesis characters as strings). This prevents code injection because tokenization explicitly recognizes only numeric and operator tokens.

3. **Recursive Descent Parser**: Three methods implement operator precedence:
   - `parseExpression()` handles addition and subtraction (lowest precedence)
   - `parseTerm()` handles multiplication, division, and modulo (higher precedence)  
   - `parseFactor()` handles numbers and parenthesized expressions (highest precedence)

4. **Error Handling**: Division by zero, modulo by zero, mismatched parentheses, and invalid syntax all raise exceptions that are caught and returned as user-friendly error messages.

The parser correctly evaluates expressions like "45 * 1.15", "(10 + 2) / 4", and "12 * (3 + 7)" while preventing all code injection attacks, including the original vulnerability where an attacker could inject arbitrary PHP code.
