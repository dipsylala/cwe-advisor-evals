## Verdict

Exploitable

## Source

`$requestData['account_type']` - user-supplied value from JSON request body, decoded from untrusted input at line 38

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

        // Business rule is evaluated directly instead of as PHP code, eliminating
        // the code injection sink. The assertion checks the account type without
        // dynamic code generation.
        $isPremium = $accountType === 'premium';
        assert($isPremium);

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

The vulnerability is in lines 20–23 of the original code, where a user-supplied `$accountType` is concatenated into a PHP expression string and passed to `assert()`. In PHP 7.x, `assert()` with a string argument evaluates that string as PHP code. An attacker can inject arbitrary PHP by supplying `account_type` values like `'=='premium') ? true : (phpinfo();//`. The fix replaces the dynamic code generation with a direct boolean comparison: `$isPremium = $accountType === 'premium'` followed by `assert($isPremium)`. This eliminates code injection by removing the eval-like behavior while preserving the assertion's logging and runtime behavior. The comparison is static and cannot be influenced by user input.

## Behaviour changes

None. The fix preserves the original control flow and assert() contract: both versions evaluate the same condition (whether `$accountType` equals `'premium'`) and either pass the assertion or raise an AssertionError. The method returns `$this->buildPremiumReport()` in both cases if the assertion passes, and raises an exception if it fails.
