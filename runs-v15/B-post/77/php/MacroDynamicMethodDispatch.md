## Verdict

Exploitable. The `$macro` variable is populated directly from `$_POST['macro']` without validation, allowing an attacker to invoke any public method on the ReportRenderer object by submitting arbitrary method names.

## Source

Line 16: `$macro = $_POST['macro'];` — untrusted user input from POST data is assigned directly to a variable used for method dispatch.

## Fix

**Vulnerable code:**
```php
function runReportMacro(ReportRenderer $renderer) {
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    $renderer->$macro();  // VULNERABLE: variable method invocation on untrusted input
}
```

**Fixed code:**
```php
function runReportMacro(ReportRenderer $renderer) {
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    // Allowlist of permitted macro verbs mapped to their corresponding methods
    $allowedMacros = [
        'refresh'      => 'refresh',
        'exportCsv'    => 'exportCsv',
        'purgeCache'   => 'purgeCache',
        'deleteReport' => 'deleteReport',
    ];

    // Only dispatch if the macro is in the allowlist
    if (!isset($allowedMacros[$macro])) {
        return;
    }

    $renderer->$macro();
}
```

## Explanation

The original code permits dynamic method invocation on any untrusted input, allowing an attacker to call methods they should not have access to. The fix introduces an explicit allowlist array (`$allowedMacros`) that maps recognized command verbs to their corresponding method names. Before invoking the method, the code validates that the user-supplied macro exists in the allowlist; if it does not match any known command, the function returns silently. This ensures only explicitly permitted methods can be invoked, eliminating the injection vector.

## Behaviour changes

- Unknown or invalid macro values now result in a silent return instead of attempting method invocation (which would previously trigger an error if the method does not exist). This is appropriate defensive behavior that prevents information leakage about available methods.
- The behavior for valid, allowlisted macros remains identical: the corresponding methods are called with no arguments, exactly as before.
- The fix preserves the empty-string check before allowlist validation, maintaining the original behavior for that edge case.
