## Verdict

Real. The code uses unsanitized user input (`$_POST['macro']`) to dynamically invoke an arbitrary method on the `ReportRenderer` object via variable method call syntax (`$renderer->$macro()`). An attacker can call any public method on the renderer, including `deleteReport()` or `purgeCache()`, bypassing intended access controls.

## Source

Line 23: `$renderer->$macro();`

The attacker-controlled input is `$_POST['macro']` (line 16), which flows directly into the method invocation without validation.

## Fix

Use a whitelist to restrict which methods can be called:

```php
function runReportMacro(ReportRenderer $renderer) {
    $macro = $_POST['macro'];
    
    if ($macro === '') {
        return;
    }
    
    // Whitelist of allowed macros
    $allowedMacros = ['refresh', 'exportCsv'];
    
    if (!in_array($macro, $allowedMacros, true)) {
        throw new InvalidArgumentException("Unknown macro: " . htmlspecialchars($macro));
    }
    
    $renderer->$macro();
}
```

Use `in_array(..., true)` to ensure strict type checking and prevent type juggling attacks.

## Explanation

CWE-77 in PHP manifests as arbitrary method invocation through variable method calls. The vulnerability arises because the attacker can invoke any public method on the renderer object—not just the intended `refresh()` and `exportCsv()` methods—including destructive operations like `deleteReport()` or `purgeCache()`.

The fix establishes an explicit whitelist of callable method names. Any attempt to invoke a method outside this set is rejected, preventing unauthorized method invocation. The whitelist approach is mandatory here: a denylist of dangerous methods would fail because new methods added to `ReportRenderer` in the future would be callable by default, and because an attacker might craft a method name to bypass pattern-based filters.

The `in_array($macro, $allowedMacros, true)` call uses strict comparison to prevent type coercion attacks (e.g., `0 == 'refresh'` evaluates to true in loose comparison).
