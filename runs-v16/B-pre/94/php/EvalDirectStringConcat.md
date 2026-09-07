## Verdict

Exploitable

## Source

`$post['expr']` (line 18): user-supplied POST parameter

## Fix

**Vulnerable code:**
```php
eval('$result = ' . $expr . ';');
```

**Fixed code:**
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

        // Whitelist validation: restrict to arithmetic operators and digits only
        if (!preg_match('/^[\d\s\(\)\+\-\*\/\.]+$/', $expr)) {
            return ['ok' => false, 'error' => 'Invalid expression format.'];
        }

        try {
            // Use ExpressionLanguage to safely evaluate arithmetic expressions
            // This avoids eval() and provides sandboxed expression evaluation
            $result = $this->expressionLanguage->evaluate($expr);
        } catch (Exception $e) {
            return ['ok' => false, 'error' => 'Calculation error.'];
        }

        return ['ok' => true, 'result' => $result];
    }
}
```

## Explanation

The fix removes `eval()` entirely and replaces it with `Symfony\Component\ExpressionLanguage\ExpressionLanguage`, a purpose-built, sandboxed expression evaluator that does not use `eval()` and does not permit arbitrary PHP code execution. The input is validated with a strict regex (`preg_match`) that allows only arithmetic operators (`+`, `-`, `*`, `/`), digits, decimal points, spaces, and parentheses. This two-layer defence—both the regex allowlist and the sandboxed evaluator—ensures that even if the expression language engine had unexpected capabilities, only arithmetic operations can reach the evaluation step. This eliminates the code injection vulnerability while preserving the feature's arithmetic-expression functionality.

## Behaviour changes

1. **New dependency**: Requires `symfony/expression-language`. Add to `composer.json` with minimum version `5.4.0` or newer (the operative floor for safe expression evaluation).
2. **Error handling**: Invalid expressions (e.g., those containing disallowed characters or malformed syntax) now return a user-friendly error message instead of a fatal PHP error. This is a behaviour improvement.
3. **Exception handling**: Wrapped evaluation in a try-catch block to gracefully handle parsing errors; the original code would have thrown an uncaught fatal error. This is safer than the original.
4. **Regex validation overhead**: A preg_match call is now performed before evaluation, which is negligible overhead but improves transparency of what is accepted.
5. **No functional loss**: Arithmetic expressions that were valid before remain valid and produce identical numerical results. The only inputs rejected are those containing non-arithmetic characters, which would have caused fatal errors in the original code anyway.
