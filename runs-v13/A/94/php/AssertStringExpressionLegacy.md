## Verdict
CONFIRMED - Code injection vulnerability via assert() string evaluation.

## Source
Lines 16-23. User-controlled `$requestData['account_type']` is concatenated into a string expression and passed to `assert()`, which executes it as PHP code on PHP 7.x.

```php
$accountType = isset($requestData['account_type']) ? $requestData['account_type'] : 'basic';
$rule = "'" . $accountType . "' == 'premium'";
assert($rule);
```

An attacker can inject code by crafting `account_type` values like `' || true || '`, which produces `assert("'' || true || '' == 'premium'")` that always evaluates true, bypassing the access check.

## Fix
Replace the string-based assertion with a direct boolean comparison. Do not use `assert()` with string arguments; use it with a boolean expression instead, or evaluate the condition separately.

```php
public function checkPremiumAccess(array $requestData)
{
    $accountType = isset($requestData['account_type']) ? $requestData['account_type'] : 'basic';

    // Evaluate the condition directly without string concatenation.
    if ($accountType !== 'premium') {
        throw new Exception('Access denied: premium account required');
    }

    return $this->buildPremiumReport();
}
```

Alternatively, if assertion-style semantics are preferred:

```php
$isPremium = $accountType === 'premium';
assert($isPremium, 'Premium account required');
```

Both approaches avoid building the expression as a string that gets executed as code.

## Explanation
The vulnerability exists because `assert($string)` on PHP 7.x compiles and executes the string as PHP code. User input flows directly into this evaluation context via string concatenation, enabling arbitrary code execution.

The fix replaces dynamic string evaluation with either:
1. Direct condition checking, which is simpler and avoids the entire assert-string pattern, or
2. assert() with a boolean expression instead of a string, which still logs a meaningful message but does not invoke code evaluation.

Both approaches eliminate the code injection sink while preserving the intended access control logic.
