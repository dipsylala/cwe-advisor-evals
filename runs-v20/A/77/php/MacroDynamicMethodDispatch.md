## Verdict

Confirmed. `runReportMacro()` takes `$macro` directly from `$_POST['macro']` - a value a report owner controls through the "custom macro" field - and uses it as a variable method name in `$renderer->$macro()` with no restriction on which method may be called. Any public method name on `ReportRenderer` (or reachable through PHP's dynamic-call resolution, e.g. `__call`) can be invoked this way, not just the four macro tokens the UI intends to expose.

## Source

`$macro = $_POST['macro'];` in `runReportMacro()` (line 16 of the original file) - attacker-controlled input from the saved report layout's custom macro field, flowing unvalidated into the dynamic method call at line 23.

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

    // Only the macro names the UI actually offers may be dispatched. This
    // closes off every other public method on ReportRenderer (and any method
    // reachable through __call) that a crafted macro token could otherwise
    // invoke.
    $allowedMacros = ['refresh', 'exportCsv', 'purgeCache', 'deleteReport'];

    if (!in_array($macro, $allowedMacros, true)) {
        return;
    }

    $renderer->$macro();
}
```

## Explanation

The dispatcher's job is to run one of a small, fixed set of named operations chosen by a template author, not to expose every method on `ReportRenderer` as a callable endpoint. The fix adds an explicit allowlist of the macro names the UI is documented to support and rejects anything else before the dynamic call is reached, using a strict (`true`) `in_array` comparison so the check cannot be defeated by type juggling.

This is a data-shape fix, not a stripping or escaping fix: there is no way to "sanitize" a method name into a safe one, because safety here is about *which* method runs, not the characters in the string. Restricting the call to the four methods the feature already exposes does not change behavior for any legitimate macro token - `refresh`, `exportCsv`, `purgeCache`, and `deleteReport` all continue to work exactly as before - while any other value (a magic method, an inherited method from a future base class, or a typo that happens to collide with an unrelated public method) is now silently ignored instead of executed. If `ReportRenderer` gains new macro-eligible methods later, they must be added to `$allowedMacros` explicitly, which keeps the exposed surface an intentional decision rather than "whatever happens to be public."
