## Verdict

Real issue confirmed. The `$macro` value from `$_POST['macro']` (line 16) reaches dynamic method dispatch on line 23 without allowlist validation, allowing an attacker to invoke any public method on the ReportRenderer object.

## Source

Line 16: `$macro = $_POST['macro'];`

Untrusted user input from POST parameter, no validation before use.

## Fix

```php
function runReportMacro(ReportRenderer $renderer) {
    // The macro token comes straight from the report's saved layout, which a
    // report owner can edit through the "custom macro" field in the UI.
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    // Allowlist of permitted macros mapped to handler methods
    $allowlist = [
        'refresh' => 'refresh',
        'exportCsv' => 'exportCsv',
        'purgeCache' => 'purgeCache',
        'deleteReport' => 'deleteReport',
    ];

    // Validate macro against allowlist
    if (!isset($allowlist[$macro])) {
        // Reject unrecognized macro
        return;
    }

    // Use the allowlist-validated handler name
    $method = $allowlist[$macro];
    $renderer->$method();
}
```

## Explanation

The fix introduces an explicit allowlist array mapping recognized macro verbs to their corresponding methods on the ReportRenderer object. Before invoking any method, the input is validated against this allowlist. Only if the macro is in the allowlist does execution proceed—and it uses the allowlist-selected canonical method name, not the original user input. Unrecognized macros are silently rejected, which prevents accidental exposure if new methods are added to ReportRenderer in the future. This follows the PHP CWE-77 remediation pattern: allowlist known command verbs and dispatch only on the validated result, never on untrusted input directly.

## Behaviour changes

- Unknown macro values now return silently instead of attempting invocation
- Only the four documented macros (refresh, exportCsv, purgeCache, deleteReport) can be invoked
- The invoking code path is identical for each allowlisted macro: method is located via the allowlist, then called on the renderer object with no parameters, with no return value captured
- Error handling: if a future developer adds a method to ReportRenderer but forgets to add it to the allowlist, the method cannot be invoked through this handler until the allowlist is updated—this is a safety feature, not a regression
