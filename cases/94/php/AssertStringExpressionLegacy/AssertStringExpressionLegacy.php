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

        // Business rule is expressed as a string and evaluated with assert() so
        // the same rule text can be logged alongside the pass/fail result.
        $rule = "'" . $accountType . "' == 'premium'";

        // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
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
