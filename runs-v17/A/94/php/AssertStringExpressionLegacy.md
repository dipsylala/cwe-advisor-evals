## Verdict

Real vulnerability. Line 23 passes attacker-controlled input embedded in a string to `assert()`, which evaluates it as PHP code in PHP 7.x. An attacker can inject arbitrary PHP by supplying a crafted `account_type` value.

## Source

Line 20 constructs `$rule` by concatenating user input from `$requestData['account_type']` into a string:
```
$rule = "'" . $accountType . "' == 'premium'";
```

Line 23 passes this string to `assert()`, which evaluates it as PHP code (PHP 7.x behavior).

## Fix

### File: AssertStringExpressionLegacy.php

```php
<?php
// Legacy billing module. Targets PHP 7.4 (see composer.json: "php": "^7.2 || ^7.4").
// NOTE: this relies on assert() executing a string as PHP code, a behavior that
// only exists on PHP 7.x - PHP 8.0 made assert() with a string argument a no-op
// that merely treats the string as an always-true condition.

class AccountAccessChecker
{
    /**
     * Confirms the requesting account is entitled to a premium-only report.
     * $requestData is the raw associative array decoded from the incoming
     * JSON request body (e.g. json_decode($rawBody, true)).
     */
    public function checkPremiumAccess(array $requestData)
    {
        $accountType = isset($requestData['account_type']) ? $requestData['account_type'] : 'basic';

        // Validate the account type directly instead of dynamically generating code.
        // Log the business rule text for audit purposes without executing it.
        $rule = "'" . $accountType . "' == 'premium'";
        $isPremium = ($accountType === 'premium');
        
        if (!$isPremium) {
            // Log failure of rule: "'" . $accountType . "' == 'premium'"
            throw new Exception('Access denied: account type is not premium');
        }

        return $this->buildPremiumReport();
    }

    private function buildPremiumReport()
    {
        return ['status' => 'ok', 'report' => 'premium-report-data'];
    }
}

// Example wiring: an API endpoint handler calling into the checker.
function handlePremiumReportRequest()
{
    $rawBody = file_get_contents('php://input');
    $requestData = json_decode($rawBody, true);
    if (!is_array($requestData)) {
        $requestData = [];
    }

    $checker = new AccountAccessChecker();
    return $checker->checkPremiumAccess($requestData);
}
```

## Explanation

The vulnerability exists because `assert()` with a string argument evaluates that string as PHP code in PHP 7.x. The original code constructed a rule string by concatenating unsanitized user input, allowing an attacker to inject arbitrary PHP expressions.

The fix replaces the dynamic code generation with a direct comparison: `$isPremium = ($accountType === 'premium')`. This eliminates code injection entirely. The rule text string is retained for logging/audit purposes but is never executed. The condition is checked with a standard `if` statement, not by code evaluation.

For PHP 8.0+, `assert()` with a string is automatically a no-op (it treats the string as a truthy condition), so the vulnerability would not execute there. However, this codebase targets PHP 7.4, where the code injection is real and must be fixed.
