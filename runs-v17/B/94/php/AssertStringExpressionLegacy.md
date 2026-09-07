## Verdict

Exploitable. Line 23 contains a code injection vulnerability via `assert($rule)` where `$rule` is built from untrusted user input (`$requestData['account_type']`). In PHP 7.x, `assert()` with a string argument evaluates it as PHP code, allowing arbitrary code execution.

## Source

`$requestData['account_type']` (line 16) — user-supplied JSON request body parameter, untrusted input decoded from `file_get_contents('php://input')` at line 37.

Data flows through string concatenation at line 20 (`$rule = "'" . $accountType . "' == 'premium'";`) into the vulnerable sink at line 23 (`assert($rule);`).

**Exploit path example:** An attacker submits JSON `{"account_type": "' . system('id') . '"}`, which constructs `$rule = "''' . system('id') . '' == 'premium'"`, and `assert()` evaluates this as PHP code, executing the injected command.

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

        // Direct boolean assertion: compare accountType against the allowed value.
        // This eliminates the code injection vulnerability by removing dynamic PHP code evaluation.
        $isPremium = ($accountType === 'premium');
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

The original code built a PHP code string (`$rule = "'" . $accountType . "' == 'premium'";`) and passed it to `assert()`. In PHP 7.x, `assert($string)` evaluates the string as PHP code, making this equivalent to `eval()`. An attacker controlling `$accountType` can inject arbitrary PHP expressions or statements.

The fix replaces the dynamic string evaluation with direct boolean logic: `$isPremium = ($accountType === 'premium');` performs a strict string comparison without any code evaluation. This eliminates the injection vector entirely while preserving the same logic — the assertion still passes only if the account type is exactly `'premium'`. The fixed code no longer builds or evaluates PHP code from untrusted input, closing the CWE-94 vulnerability.

## Behaviour changes

The assertion now uses direct boolean logic instead of PHP code evaluation. The behavior at the application level remains identical: `checkPremiumAccess()` proceeds only when `$accountType === 'premium'` and fails the assertion otherwise. No silent behavior changes occur — the function either returns the premium report or triggers an assertion failure, exactly as before. The removal of dynamic code evaluation has no impact on the return value, error handling, or side effects of the original code.
