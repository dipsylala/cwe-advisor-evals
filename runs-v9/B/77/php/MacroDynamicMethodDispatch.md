## Verdict

Exploitable. `$macro` is taken directly from `$_POST['macro']` (attacker/report-owner controlled) with no allowlist or validation, and is used as the method name in a dynamic method call `$renderer->$macro()`. Any public method reachable on `$renderer` - not just the four macro handlers the author intended (`refresh`, `exportCsv`, `purgeCache`, `deleteReport`) - can be invoked by name. This is CWE-77 (command injection against a non-shell interpreter: PHP's own dynamic-dispatch mechanism acting as the "command interpreter" for a bespoke macro syntax), matching the taint sink `$obj->$method()` documented for PHP.

## Source

`$_POST['macro']` in `runReportMacro()`, line 16 of `MacroDynamicMethodDispatch.php` - a macro token from a report layout's "custom macro" field, submitted with the request and used unfiltered.

## Fix

Vulnerable code:

```php
function runReportMacro(ReportRenderer $renderer) {
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    // SAST FINDING: CWE-77 reported here. Sink is the next statement.
    $renderer->$macro();
}
```

Fixed code:

```php
class ReportRenderer {
    public function refresh() { /* ... */ }
    public function exportCsv() { /* ... */ }
    public function purgeCache() { /* ... */ }
    public function deleteReport() { /* ... */ }
}

// Allowlist: only these exact tokens may ever reach dynamic dispatch, mapped
// to the specific method they are permitted to invoke.
const ALLOWED_REPORT_MACROS = [
    'refresh'      => 'refresh',
    'exportCsv'    => 'exportCsv',
    'purgeCache'   => 'purgeCache',
    'deleteReport' => 'deleteReport',
];

function runReportMacro(ReportRenderer $renderer) {
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    if (!array_key_exists($macro, ALLOWED_REPORT_MACROS)) {
        // Unknown macro token - reject rather than attempt dispatch.
        return;
    }

    $method = ALLOWED_REPORT_MACROS[$macro];
    $renderer->$method();
}
```

## Explanation

The fix replaces unfiltered dynamic dispatch with a hardcoded allowlist that maps each of the four legitimate macro tokens to the exact method name it may invoke. The raw `$_POST['macro']` value is now only ever used as a lookup key into `ALLOWED_REPORT_MACROS`, never as the argument to `->$macro()` itself; the value that actually reaches the dispatch call (`$method`) is the allowlist's own trusted string, not attacker-controlled input (breaking taint per the allowlist canonicalization pattern). Any token that isn't one of the four known macros - including internal/unintended method names, magic methods, or arbitrary strings - is rejected before dispatch ever occurs, closing the arbitrary-method-invocation path while leaving all four legitimate macros working exactly as before.

## Behaviour changes

A macro token that is non-empty but not one of the four allowlisted values now causes the function to return silently instead of reaching `$renderer->$macro()`. In the original code such a value either invoked an unintended method that happens to exist on `ReportRenderer` (the injection this fix closes) or, for a name matching no method, triggered a PHP fatal `Error: Call to undefined method`. Under the fix both cases resolve to a silent no-op instead. This is intentional: a rejected/unmatched command verb returning without executing anything is the documented remediation (Remediation Steps: "Reject any input that does not match a known command verb exactly; do not attempt partial matches or fallthrough execution"), and the four legitimate macros retain identical dispatch behaviour (same method, no arguments, same return value discarded) since the allowlist maps each token to itself. No other arguments, return-value handling, or control flow changed.
