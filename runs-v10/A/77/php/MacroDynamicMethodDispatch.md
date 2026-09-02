## Verdict

The vulnerability is **confirmed**. The code on line 23 uses a user-controlled value (`$macro` from `$_POST['macro']`) as a method name without any allowlist validation. This enables an attacker with control over the saved report layout to invoke any method on the `ReportRenderer` object, including inherited or magic methods that may have unintended effects.

## Source

Line 16: `$macro = $_POST['macro'];`

User-supplied input is read from the POST parameter `macro`, which comes from the custom macro field edited by report owners. This value flows directly to line 23 without sanitization or validation.

Line 23: `$renderer->$macro();`

The macro name is used as a dynamic method name without restricting which methods can be called.

## Fix

Replace the dynamic invocation with an allowlist-based dispatcher:

```php
function runReportMacro(ReportRenderer $renderer) {
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    $allowedMethods = ['refresh', 'exportCsv', 'purgeCache', 'deleteReport'];

    if (!in_array($macro, $allowedMethods, true)) {
        throw new InvalidArgumentException('Unsupported macro: ' . $macro);
    }

    $renderer->$macro();
}
```

The allowlist explicitly defines which methods are safe to call, and the code rejects any method name not in that list before invoking it.

## Explanation

The issue is that dynamic method dispatch (`$renderer->$macro()`) with unsanitized input allows an attacker to call any method on the object, not just the intended ones. Even though only four methods are defined on `ReportRenderer`, an attacker could call inherited methods from parent classes, trigger magic methods, or exploit reflection capabilities if those exist on the object.

The fix uses a strict allowlist (`in_array()` with the third parameter `true` for type-safe comparison) to ensure only known-safe methods can be invoked. This is the standard control for dynamic command dispatch: enumerate the safe commands and reject everything else before execution.
