## Verdict

Confirmed exploitable. The vulnerability allows an attacker to invoke any public method on the ReportRenderer object through untrusted input in the POST parameter, without restriction.

## Source

**File:** MacroDynamicMethodDispatch.php  
**Line:** 23  
**Sink:** `$renderer->$macro()` (dynamic method invocation via variable dispatch)  
**Source:** `$_POST['macro']` (untrusted user input)

**Data Flow:**
1. Line 16: Untrusted input extracted from `$_POST['macro']`
2. Line 18-20: Empty string check only; no allowlist validation
3. Line 23: Variable dispatch `$renderer->$macro()` invokes any method by name

The empty-string guard is insufficient: it prevents empty method names but permits any non-empty string the attacker supplies. The renderer object exposes four public methods (`refresh`, `exportCsv`, `purgeCache`, `deleteReport`), but without an allowlist, an attacker could call any other public method that exists on the object or its parents, or exploit reflection/magic methods.

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

    // FIXED: Validate against an allowlist of known command verbs.
    // Only recognized macros are permitted to execute.
    $allowedMacros = ['refresh', 'exportCsv', 'purgeCache', 'deleteReport'];
    
    if (!in_array($macro, $allowedMacros, true)) {
        return;
    }
    
    $renderer->$macro();
}
```

## Explanation

The fix introduces an explicit allowlist of known, safe macro verbs (`refresh`, `exportCsv`, `purgeCache`, `deleteReport`). Before dynamic dispatch, the input is validated using `in_array()` with strict comparison (`true` parameter) to ensure exact, type-safe matching. If the macro name does not appear in the allowlist, the function returns early without invoking any method.

This aligns with CWE-77 PHP remediation guidance: dynamic dispatch on untrusted input is replaced with a lookup in a fixed allowlist array. The variable dispatch `$renderer->$macro()` only executes after the allowlist check confirms the name is permitted. No other public methods, inherited methods, or magic methods can be invoked.

The `in_array()` function with strict comparison (`true`) performs an exact match without type juggling, preventing bypasses via type confusion (e.g., `0 == 'refresh'` in loose comparison).

## Behaviour changes

- **Allowed input:** Exactly matches one of `refresh`, `exportCsv`, `purgeCache`, or `deleteReport` → method executes as before
- **Disallowed input:** Any name not in the allowlist (including misspellings, case variations, empty string) → function returns without method invocation
- **Rejection:** Case-sensitive; `REFRESH` and `Refresh` are rejected. Casing must match exactly.
- **Newline bypass:** Trailing whitespace or newlines (e.g., `refresh\n`) are rejected by exact-match comparison
- **Return value:** Unchanged; method's return value (if any) passes through to caller
- **Performance:** Negligible; `in_array()` on a small fixed array (4 items) is constant-time

No method signatures, execution logic, or legitimate use cases are affected by this change.
