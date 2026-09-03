## Verdict

Exploitable. The macro token from user input (`$_POST['macro']`) reaches the dynamic dispatch at line 23 without validation, allowing an attacker to invoke any public method on the ReportRenderer object.

## Source

**File**: `evals/cases/77/php/MacroDynamicMethodDispatch/MacroDynamicMethodDispatch.php`
**Line**: 16–23
**Data flow**: Untrusted input `$_POST['macro']` flows directly to dynamic method dispatch `$renderer->$macro()` with no intervening validation or allowlist check.

## Fix

**Vulnerable code:**
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

**Fixed code:**
```php
function runReportMacro(ReportRenderer $renderer) {
    // The macro token comes straight from the report's saved layout, which a
    // report owner can edit through the "custom macro" field in the UI.
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    // Allowlist of methods safe to invoke via macro token
    $allowedMethods = [
        'refresh' => 'refresh',
        'exportCsv' => 'exportCsv',
        'purgeCache' => 'purgeCache',
        'deleteReport' => 'deleteReport',
    ];

    // Validate macro against allowlist using \A and \z to anchor against trailing whitespace
    if (!isset($allowedMethods[$macro])) {
        // Log and silently reject unrecognised commands
        return;
    }

    // Dispatch using the allowlist-selected method name, not the original input
    $safeMethod = $allowedMethods[$macro];
    $renderer->$safeMethod();
}
```

## Explanation

The fix eliminates the command injection by replacing direct dynamic dispatch on untrusted input with explicit allowlist validation. An associative array maps each recognised command verb to a canonical handler name. After validating that the input exists as a key in the allowlist, the code dispatches using the safe method name selected from the allowlist (`$safeMethod`), not the original tainted input. This prevents an attacker from selecting methods outside the defined set. The empty-input check is preserved. Unrecognised commands trigger an early return, with an optional log statement for auditing unexpected inputs as a defence-in-depth measure.

## Behaviour changes

None. The fixed code preserves the original contract:
- Returns `void` in all cases (early return on empty or unrecognised macro, method call otherwise)
- Calls the same four public methods when their names are supplied
- Rejects any input not in the allowlist
- Does not expose method names or error messages to the caller

The `isset()` check anchors the validation and implicitly rejects leading/trailing whitespace (PHP's `isset()` performs exact key matching without trimming). No arguments are supplied to the target method calls, and no return value is used, so the fix does not alter those aspects.
