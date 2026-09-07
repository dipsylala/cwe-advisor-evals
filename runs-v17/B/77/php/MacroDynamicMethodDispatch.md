## Verdict

**CONFIRMED: Real vulnerability.** The code performs dynamic method dispatch on untrusted user input (`$_POST['macro']`) without allowlisting. An attacker can invoke any method on the `ReportRenderer` object, not only the intended ones.

## Source

The macro command name flows from `$_POST['macro']` (line 16) into the dynamic method dispatch at line 23, with only an empty-string check for validation.

## Fix

Replace the unsafe dynamic dispatch with an allowlist-based lookup that maps allowed macro names to their corresponding methods.

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

    // Allowlist of safe macro commands mapped to their handler methods
    $allowedMacros = [
        'refresh' => 'refresh',
        'exportCsv' => 'exportCsv',
        'purgeCache' => 'purgeCache',
        'deleteReport' => 'deleteReport',
    ];

    // Only dispatch if macro is in the allowlist; reject unknown macros
    if (!isset($allowedMacros[$macro])) {
        error_log("Rejected unknown macro: " . var_export($macro, true));
        return;
    }

    // Dispatch to the allowlist-selected method, not the original input
    $method = $allowedMacros[$macro];
    $renderer->$method();
}
```

## Explanation

The fix implements the primary defence for CWE-77 command injection in custom interpreters: an explicit allowlist that maps user-supplied command verbs to a fixed set of safe handlers. Instead of passing the untrusted `$macro` value directly to dynamic dispatch, the code now looks up the input in an `$allowedMacros` array and only invokes the allowlist-selected method. Any macro name not present in the allowlist is rejected and logged for audit. This breaks the taint chain: the dispatcher (`$renderer->$method()`) now receives a value from the allowlist, not the original user input. An attacker cannot invoke unintended methods, even if they know method names or use callable string syntax like `Class::method`, because only the four hardcoded keys in the allowlist are accepted.

## Behaviour changes

- **Before**: Any macro value (except empty string) invokes a method by that name on the renderer.
- **After**: Only the four allowlisted macros (`refresh`, `exportCsv`, `purgeCache`, `deleteReport`) execute. Unknown macros are silently rejected and logged.
- **No breaking change for legitimate use**: All intended macros continue to work identically.
