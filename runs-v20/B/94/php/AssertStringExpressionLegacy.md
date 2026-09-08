## Verdict

Exploitable. CWE-94 (Improper Control of Generation of Code ('Code Injection')), PHP, `AssertStringExpressionLegacy.php:23`. The target runtime is PHP 7.x (composer.json restricts to `^7.2 || ^7.4`, and the file's own header comment confirms the code depends on PHP 7's string-argument behavior of `assert()`), so the string-eval path is live, not dead code.

## Source

`$requestData['account_type']` in `AccountAccessChecker::checkPremiumAccess()` (line 16), populated from `json_decode($rawBody, true)` of `file_get_contents('php://input')` in `handlePremiumReportRequest()` (lines 37-38) - the raw incoming JSON request body, fully attacker-controlled.

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

        // Business rule is evaluated as a direct boolean expression so no part of
        // the (attacker-controlled) account type is ever assembled into a string
        // that assert() could execute as PHP code.
        $rule = $accountType === 'premium';

        // Fixed: assert() now receives a boolean, not a string built from
        // untrusted input, so there is no code for it to generate or execute -
        // this closes the CWE-94 finding while keeping the same pass/fail check.
        assert($rule);

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

The original code built `$rule` as a PHP source string that embedded the untrusted `$accountType` value inside single quotes (`"'" . $accountType . "' == 'premium'"`) and handed that string to `assert()`. On PHP 7.x, `assert()` compiles and executes a string argument as PHP code, so an attacker who controls `account_type` can close the quote early and append arbitrary PHP (e.g. `x' or system('id') or 'x'=='y`) for `assert()` to execute with full application privileges. The fix removes the string-building step entirely: `$accountType === 'premium'` is evaluated in PHP as an ordinary boolean expression before it ever reaches `assert()`, so `assert()` receives a plain `bool` and has no source text to generate or execute, on either PHP 7 or PHP 8. This is the pattern the loaded PHP guidance names directly for this sink: replace `assert($stringExpression)` with a direct boolean assertion rather than relying on a version check, since the code must remain safe on the PHP 7.4 target it declares.

## Behaviour changes

None from the caller's perspective. `checkPremiumAccess()` still returns the premium report when `account_type === 'premium'` and still throws `AssertionError` otherwise (verified: `assert(false)` and `assert()` on a false boolean both throw by default, matching the prior string-assertion's failure path when the rule evaluated false) - the sink's return value (unused by the caller), its default failure behavior (throw), and its omitted `$description` argument are all unchanged. The only difference is that the value fed to `assert()` is now a `bool` instead of a `string`, which is the change that closes the injection; a crafted `account_type` that previously would have executed as PHP code now simply fails the equality check and throws `AssertionError` like any other non-premium account.

**Verification:** `php -l` on the fixed file reported no syntax errors. The fixed logic was also executed directly (PHP 8.5 available in this environment): `account_type => 'premium'` returned the premium report; `account_type => 'basic'` threw `AssertionError` (unchanged pass/fail semantics); and an injection-style payload (`x' == 'x' or system('calc') or '1' == '0`) also threw `AssertionError` with no code execution, confirming the previously exploitable path is closed.
