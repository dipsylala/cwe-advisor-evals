## Verdict
The code injects user-supplied input into a string evaluated by `assert()`, which executes the string as PHP code in PHP 7.x. This is CWE-94 code injection.

## Source
Line 16: `$accountType = isset($requestData['account_type']) ? $requestData['account_type'] : 'basic';`

User-controlled `account_type` field from JSON request body reaches the checker without validation.

## Fix
### File: AssertStringExpressionLegacy.php
```php
<?php
// Legacy billing module. Targets PHP 7.4 (see composer.json: "php": "^7.2 || ^7.4").
// NOTE: this file previously relied on assert() executing a string as PHP code.
// This has been remediated to use direct comparison instead of assert().

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

        // Verify premium access with a direct comparison instead of assert().
        // This avoids CWE-94 code injection through assert().
        // The condition is explicitly checked rather than evaluated as PHP code.
        if ($accountType !== 'premium') {
            throw new Exception('Access denied: premium account required');
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
The fix replaces the code-generation mechanism (`assert()` with a string) with a direct value comparison. Instead of concatenating the untrusted `$accountType` into a string and evaluating it, the code now checks if `$accountType` is exactly the string `'premium'` using the `!==` operator. If the check fails, an exception is thrown, making the access-control failure explicit and secure. This eliminates the injection point entirely—user input is never evaluated as code.
