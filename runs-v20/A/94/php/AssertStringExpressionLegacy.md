## Verdict

Confirmed. `assert()` is called with a string built by concatenating attacker-controlled
`$requestData['account_type']` into what becomes PHP source text. On PHP 7.x, `assert()`
compiles and executes a string argument as PHP code, so a request body such as
`{"account_type": "x'; system($_GET['c']); //"}` closes the quoted literal and injects
arbitrary PHP that executes in the process. This is CWE-94.

## Source

`$requestData['account_type']`, read from the JSON body of an incoming HTTP request via
`json_decode($rawBody, true)` in `handlePremiumReportRequest()`, then passed unchanged into
`AccountAccessChecker::checkPremiumAccess()`.

## Fix

### File: AssertStringExpressionLegacy.php

```php
<?php
// Legacy billing module. Targets PHP 7.4 (see composer.json: "php": "^7.2 || ^7.4").

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

        // Business rule is evaluated as a plain boolean comparison. The rule
        // text used to be built as a string and handed to assert(), which on
        // PHP 7.x compiles and executes a string argument as PHP code -
        // letting $accountType inject arbitrary code. A human-readable
        // description is kept for logging, but it is never evaluated.
        $isPremium = $accountType === 'premium';
        $ruleDescription = "account_type == 'premium'";

        if (!$isPremium) {
            throw new \RuntimeException(sprintf(
                'Access denied: rule "%s" failed for account_type=%s',
                $ruleDescription,
                $accountType
            ));
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

The vulnerable line built the rule as PHP source (`"'" . $accountType . "' == 'premium'"`) and
handed that string to `assert()`. `assert()`'s string-argument form is documented to `eval()`
the string as PHP code on PHP 7.x (this behavior was removed in PHP 8.0, where a string
argument is instead treated as an always-true description with a deprecation notice) - so any
character the attacker puts in `account_type`, including a closing quote followed by a
semicolon, becomes part of the executed program rather than data being compared.

The fix drops the string-eval form of `assert()` entirely and replaces it with a direct `===`
comparison, so `$accountType` is only ever treated as a data value, never as code text - this
closes the injection regardless of PHP version. It also stops relying on `assert()` as the
actual access-control gate: PHP's assertions are commonly disabled in production
(`zend.assertions = -1`, the recommended production setting per the PHP manual), which compiles
`assert()` calls away completely, so a security decision expressed only through `assert()` may
silently never run. The gate is now an explicit `if`/`throw`, so it enforces unconditionally,
independent of the `zend.assertions` ini setting. The human-readable rule text is preserved
for logging/error messages but is only ever interpolated into a string for display, never
passed to any code-evaluation sink.
