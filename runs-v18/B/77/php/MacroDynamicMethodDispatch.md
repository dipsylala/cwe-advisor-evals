## Verdict

Exploitable. Untrusted input from `$_POST['macro']` reaches dynamic method invocation on line 23 without allowlist validation, allowing an attacker to call any public method on the ReportRenderer object.

## Source

`$_POST['macro']` (user-supplied POST parameter, read on line 16)

## Explanation

The vulnerable code invokes an arbitrary method on the renderer object based on user input with minimal validation (only an empty string check). An attacker can submit any method name to call unintended functionality. The fix introduces an explicit allowlist mapping each valid macro verb to its corresponding method. Only macros present in the allowlist are permitted to execute; the lookup result (not the original user input) is used in the dispatch call. This prevents invocation of unallowlisted methods, including dangerous ones like `deleteReport`.

The fix follows CWE-77 PHP-specific guidance: a custom command interpreter (macro parser) must never dispatch directly on untrusted input. Instead, the verb is validated against a fixed allowlist, and only the allowlisted handler reference reaches the dispatch call.

## Behaviour changes

The fixed code introduces an allowlist array and an early return for unknown macros. For valid macros in the allowlist, method invocation is identical to the original. For unknown or disallowed macros, the function returns early instead of attempting dispatch. This is the intended security hardening: macro tokens not explicitly allowlisted will no longer execute. The empty string check on line 18 is preserved, maintaining the original early-return behaviour for that case.

## Fix

### File: MacroDynamicMethodDispatch.php

```php
<?php
// Report macro engine: template authors embed tokens like {{refresh}} or
// {{exportCsv}} inside a saved report layout, and this handler resolves each
// token to a method call on the report renderer that built the page.

class ReportRenderer {
    public function refresh() { /* ... */ }
    public function exportCsv() { /* ... */ }
    public function purgeCache() { /* ... */ }
    public function deleteReport() { /* ... */ }
}

function runReportMacro(ReportRenderer $renderer) {
    // The macro token comes straight from the report's saved layout, which a
    // report owner can edit through the "custom macro" field in the UI.
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    // Allowlist of valid macro verbs
    $allowedMacros = [
        'refresh' => 'refresh',
        'exportCsv' => 'exportCsv',
        'purgeCache' => 'purgeCache',
        // Note: deleteReport intentionally omitted from allowlist
    ];

    // Validate macro against allowlist
    if (!array_key_exists($macro, $allowedMacros)) {
        // Reject unknown macros
        return;
    }

    // Invoke only the allowlisted method
    $renderer->{$allowedMacros[$macro]}();
}
```
