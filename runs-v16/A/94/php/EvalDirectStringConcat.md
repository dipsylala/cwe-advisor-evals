## Verdict
The vulnerability is real. Line 26 passes unsanitized user input from `$post['expr']` directly to `eval()`, enabling arbitrary code execution even in an admin context.

## Source
Line 26 in `QuickCalculationHandler::handleRequest()`:
```php
eval('$result = ' . $expr . ';');
```

The `$expr` parameter originates from `$post['expr']` (line 18) with no validation beyond an empty check. An attacker can inject PHP code; for example, `expr=1; system("id");` would execute the shell command.

## Fix
Replace `eval()` with a safe math expression evaluator. Validate input strictly, then evaluate using either a whitelist validator with `bc` or a dedicated math parser:

**Option 1: Whitelist validation + bc command**
```php
// Validate: only digits, operators, parentheses, decimal point, whitespace
if (!preg_match('/^[\d\s.+\-*/%()]+$/', $expr)) {
    return ['ok' => false, 'error' => 'Invalid expression format.'];
}

// Evaluate using bc (safe, no code execution)
$result = shell_exec('echo "' . addslashes($expr) . '" | bc -l');
if ($result === null) {
    return ['ok' => false, 'error' => 'Calculation failed.'];
}
```

**Option 2: Use a dedicated expression parser library** (e.g. `symfony/expression-language` or `phpmath/mathexec`)
```php
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;

$expressionLanguage = new ExpressionLanguage();
try {
    $result = $expressionLanguage->evaluate($expr);
} catch (\Exception $e) {
    return ['ok' => false, 'error' => 'Invalid expression.'];
}
```

## Explanation
`eval()` compiles and executes arbitrary PHP code. Even with admin-only access, accepting untrusted expressions violates the principle that input must be validated before code generation. The whitelist approach restricts input to arithmetic syntax before evaluation. A purpose-built expression parser is safer because it only interprets the expression grammar you define, preventing escape from the arithmetic domain. Both approaches eliminate the code injection risk while preserving calculator functionality.
