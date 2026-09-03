## Verdict

Exploitable. The `eval()` function at line 26 executes arbitrary PHP code derived directly from user input (`$post['expr']`). An attacker can inject any PHP code (e.g., `system('whoami')`, `phpinfo()`, or database compromise) and it executes with full application privileges.

## Source

User-supplied arithmetic expression: `$post['expr']` parameter from HTTP POST request

## Fix

**Vulnerable code:**
```php
eval('$result = ' . $expr . ';');
```

**Fixed code:**
```php
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;

$evaluator = new ExpressionLanguage();
try {
    $result = $evaluator->evaluate($expr);
} catch (\Throwable $e) {
    return ['ok' => false, 'error' => 'Invalid expression.'];
}
```

**Library recommendation:** `symfony/expression-language` - add to `composer.json` with version constraint from the official Symfony releases. This library safely parses and evaluates expressions without executing arbitrary PHP code.

## Explanation

The `eval()` sink executes any PHP code in the input string, providing no isolation or restriction. Replacing it with `Symfony\Component\ExpressionLanguage\ExpressionLanguage` moves evaluation into a controlled parser that only interprets mathematical expressions and variable references, not arbitrary PHP. The ExpressionLanguage component parses the input into an AST and evaluates it in a restricted context, preventing language-level code injection. The try-catch block handles malformed expressions gracefully without exposing parsing errors to the client.

## Behaviour changes

- **Exception handling added:** The original code would throw a PHP parse error if the expression was malformed; the fixed code catches the exception and returns a user-friendly error message, improving error handling.
- **Syntax difference:** ExpressionLanguage uses its own expression syntax (which overlaps with PHP arithmetic but is more restrictive). For simple arithmetic like `12 * (3 + 7)`, the syntax is identical, but more complex PHP expressions (function calls, variable assignment, string operations) will be rejected rather than executed.
- **No PHP language constructs:** The fixed code forbids PHP language constructs like `eval()`, `isset()`, `empty()`, method calls, and class instantiation - only variable references and mathematical operators are allowed, eliminating the injection vector entirely.
