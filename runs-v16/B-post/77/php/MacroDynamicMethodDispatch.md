## Verdict

CWE-77 (Improper Neutralization of Special Elements used in a Command) is confirmed. The code invokes an arbitrary method on the ReportRenderer object based on unvalidated user input (`$_POST['macro']`), allowing an attacker to call any public method on the renderer instance, including methods not intended for macro invocation.

## Source

**File:** `evals/cases/77/php/MacroDynamicMethodDispatch/MacroDynamicMethodDispatch.php`  
**Line:** 23  
**Code:** `$renderer->$macro();`

**Data flow:**
- Source: `$_POST['macro']` (user-supplied POST parameter)
- Intermediate: Variable `$macro` assigned from POST without validation
- Sink: Dynamic method invocation `$renderer->$macro()` where `$macro` is attacker-controlled
- Only validation: Empty string check at line 18, which is insufficient to prevent method name injection

## Fix

Replace the unsafe dynamic dispatch with an allowlist that maps valid macro names to the intended methods. Only invoke methods that are explicitly allowed:

```php
function runReportMacro(ReportRenderer $renderer) {
    // The macro token comes straight from the report's saved layout, which a
    // report owner can edit through the "custom macro" field in the UI.
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    // Allowlist of valid macro verbs to their corresponding methods
    $allowedMacros = [
        'refresh' => true,
        'exportCsv' => true,
        'purgeCache' => true,
        'deleteReport' => true,
    ];

    // Invoke only if the macro is in the allowlist
    if (!isset($allowedMacros[$macro])) {
        // Unrecognized macro; reject silently or log for monitoring
        return;
    }

    $renderer->$macro();
}
```

## Explanation

The vulnerability occurs because `$renderer->$macro()` uses untrusted input to select which method to invoke. Even though the ReportRenderer class only has four intended public methods, there is no enforcement preventing an attacker from calling any public method on the object, including methods inherited from parent classes or potentially dangerous lifecycle methods.

The fix implements an explicit allowlist: only the four intended macros (`refresh`, `exportCsv`, `purgeCache`, `deleteReport`) are permitted. Before invoking `$renderer->$macro()`, the code checks whether the requested macro is in the allowlist. If not, the function returns early (rejects the request). After allowlist validation, the allowed method name is still passed to the dynamic invocation, but only after confirming it matches a known-safe value.

This pattern follows CWE-77 remediation guidance for PHP: never let untrusted input choose which function or method is invoked directly; only the allowlist lookup result should reach the dispatch call. The allowlist acts as a gate, ensuring only intended methods can be called through the macro system.

## Behaviour changes

- **Allowed macros:** Requests for `refresh`, `exportCsv`, `purgeCache`, and `deleteReport` continue to work as before.
- **Unrecognized macros:** Any macro name not in the allowlist is silently rejected (returns without invoking a method). Legitimate callers use only the four known verbs and are unaffected.
- **Attack surface reduction:** An attacker can no longer invoke arbitrary methods on the ReportRenderer object by crafting a POST parameter with a method name; only the four allowlisted macros are reachable.
- **No breaking changes:** The public interface and normal usage remain identical; only injection attempts are blocked.

Optional: Add logging when an unrecognized macro is rejected to enable monitoring for suspicious activity:

```php
if (!isset($allowedMacros[$macro])) {
    error_log("Unrecognized macro: " . $macro);
    return;
}
```
