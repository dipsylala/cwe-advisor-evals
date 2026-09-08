## Verdict
True positive. The dynamic method invocation on line 23 accepts an attacker-controlled value without validation, allowing arbitrary method calls.

## Source
Line 16 reads the macro name from `$_POST['macro']`, a user-controlled source. Line 23 uses this value in a dynamic method call `$renderer->$macro()` without first validating it against the set of intended macro handlers.

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

    // Allowlist of permitted macro methods to prevent arbitrary method invocation
    $allowedMethods = ['refresh', 'exportCsv', 'purgeCache', 'deleteReport'];
    
    if (!in_array($macro, $allowedMethods, true)) {
        return;
    }

    $renderer->$macro();
}
```

## Explanation
The vulnerability occurs because an attacker can craft a `$_POST['macro']` value to invoke any public method on the ReportRenderer object, bypassing the intended macro interface. The remediation uses an explicit allowlist to restrict invocation to only the designed macro handlers. The `in_array()` call with strict type checking (`true` as the third parameter) ensures only exact string matches are accepted, preventing both type confusion and unintended method names. If the macro value is not in the allowlist, execution returns early without invoking any method.
