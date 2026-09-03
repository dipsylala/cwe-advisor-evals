## Verdict

Exploitable. User input from `$_POST['macro']` reaches a dynamic method invocation without allowlisting, permitting calls to any public method on the ReportRenderer object.

## Source

Line 16: `$macro = $_POST['macro'];` - attacker controls the macro name via POST parameter.

## Fix

**Vulnerable code:**
```php
function runReportMacro(ReportRenderer $renderer) {
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    // SAST FINDING: CWE-77 reported here - $macro reaches dynamic dispatch unvalidated
    $renderer->$macro();
}
```

**Fixed code:**
```php
function runReportMacro(ReportRenderer $renderer) {
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    // Allowlist of permitted macro commands
    $allowedMacros = ['refresh', 'exportCsv', 'purgeCache', 'deleteReport'];

    // Validate macro against allowlist before dispatch
    if (!in_array($macro, $allowedMacros, true)) {
        return;
    }

    $renderer->$macro();
}
```

## Explanation

The fix introduces an allowlist of known-safe method names and validates the untrusted macro input against it before allowing dynamic dispatch. Only the macro values present in the allowlist can reach the method invocation, preventing an attacker from calling unintended methods. The validation uses `in_array()` with strict type checking (`true` parameter) to ensure exact string matching, and `\A...\z` anchoring is not needed here since `in_array()` compares whole strings by default. The check is performed before the sink, so only allowlisted values are used in dynamic dispatch.

## Behaviour changes

None. The original code returns without action if macro is empty or not in the allowlist. The fixed code preserves this behaviour while adding validation. No arguments are passed to the methods, no return values are used, and the method calls are invoked identically—only their accessibility is now restricted to known-safe handlers.
