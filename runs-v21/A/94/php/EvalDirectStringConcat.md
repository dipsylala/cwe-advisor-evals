## Verdict
Confirmed. The code uses `eval()` with unsanitized user-supplied input from `$post['expr']`, allowing arbitrary PHP code injection.

## Source
The vulnerability is on line 26:
```php
eval('$result = ' . $expr . ';');
```

The `$expr` parameter comes directly from untrusted POST data (`$post['expr']`) and is concatenated into an `eval()` statement without any validation. An attacker can inject arbitrary PHP code.

## Fix

### File: QuickCalculationHandler.php
```php
<?php
/**
 * Admin-only "quick calculation" tool. Lets an operator type an arithmetic
 * expression (e.g. "12 * (3 + 7)") and see the result without opening a
 * separate calculator. Targets PHP 8.1.
 */

use Symfony\Component\ExpressionLanguage\ExpressionLanguage;

class QuickCalculationHandler
{
    private $expressionLanguage;

    public function __construct()
    {
        $this->expressionLanguage = new ExpressionLanguage();
    }

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
            $result = $this->expressionLanguage->evaluate($expr);
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => 'Invalid expression.'];
        }

        return ['ok' => true, 'result' => $result];
    }
}
```

## Explanation
The fix eliminates the `eval()` call entirely and replaces it with Symfony's `ExpressionLanguage` component. This library safely parses and evaluates expressions in a controlled sandbox that:

- Does not allow arbitrary PHP code execution
- Only permits evaluated expressions with arithmetic operators and function calls within the configured scope
- Throws an exception on invalid or dangerous expressions, which is caught and handled gracefully

The user-supplied `$expr` is passed to `evaluate()` as data, not as code to be constructed via string concatenation. The library parses it as an expression in its own language, preventing code injection.

Symfony's ExpressionLanguage is a standard, maintained library widely used in PHP applications for exactly this use case. Dependency: `symfony/expression-language` (any recent stable version).
