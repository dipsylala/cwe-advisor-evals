## Verdict

Real. The dynamic method invocation on line 23 accepts an unsanitized method name from user input, allowing an attacker to invoke any public method on the ReportRenderer object, including unintended ones.

## Source

```php
function runReportMacro(ReportRenderer $renderer) {
    // The macro token comes straight from the report's saved layout, which a
    // report owner can edit through the "custom macro" field in the UI.
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
    $renderer->$macro();
}
```

The vulnerability: `$_POST['macro']` flows directly into the dynamic method call `$renderer->$macro()` without validation.

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

    // Whitelist of allowed macro methods
    $allowedMacros = ['refresh', 'exportCsv', 'purgeCache', 'deleteReport'];
    
    // Validate that the macro is in the whitelist before invoking
    if (!in_array($macro, $allowedMacros, true)) {
        return;
    }

    $renderer->$macro();
}
```

## Explanation

The fix uses a whitelist to restrict which methods can be dynamically invoked. Only methods explicitly listed in `$allowedMacros` are callable; any attempt to invoke an unlisted method is silently rejected. The `in_array()` check uses strict comparison (`true` as the third parameter) to prevent type juggling attacks. This ensures that only the intended public API methods (`refresh`, `exportCsv`, `purgeCache`, `deleteReport`) can be called, preventing an attacker from invoking other public methods like `__toString()`, `__call()`, or any other unintended methods that might exist on the object.
