## Verdict

Confirmed. `runReportMacro()` takes the `macro` value straight from `$_POST['macro']` (a report owner's saved "custom macro" field) and uses it as a PHP variable method name in `$renderer->$macro()` with no allowlist or validation. Because PHP resolves `$obj->$name()` at runtime from whatever string `$name` holds, an attacker who controls the `macro` field controls which method on `ReportRenderer` executes. Today that is limited to the four public methods shown, but the dispatch is unconstrained by design: any public method later added to `ReportRenderer` (or reachable through it, e.g. inherited from a parent class or trait) becomes callable through this same field without a corresponding code change here, and there is no server-side record of which macro names were actually intended to be exposed to report authors.

## Source

`$_POST['macro']` in `runReportMacro()` (line 16), attacker-controlled: it is read from the "custom macro" field of a saved report layout, which the code's own comment states a report owner can edit through the UI.

## Fix

```php
class ReportRenderer {
    private const ALLOWED_MACROS = ['refresh', 'exportCsv', 'purgeCache', 'deleteReport'];

    public function refresh() { /* ... */ }
    public function exportCsv() { /* ... */ }
    public function purgeCache() { /* ... */ }
    public function deleteReport() { /* ... */ }
}

function runReportMacro(ReportRenderer $renderer) {
    $macro = $_POST['macro'];

    if ($macro === '') {
        return;
    }

    if (!in_array($macro, ReportRenderer::ALLOWED_MACROS, true)) {
        // Reject unknown macro tokens instead of dispatching them.
        throw new InvalidArgumentException('Unknown report macro: ' . $macro);
    }

    $renderer->$macro();
}
```

## Explanation

The fix replaces implicit trust in the request value with an explicit allowlist that enumerates every method the macro engine is permitted to invoke. `in_array($macro, ..., true)` uses strict comparison so the check cannot be satisfied by type-juggling tricks (numeric-looking strings, etc.), and only an exact, case-sensitive match against one of the four intended method names passes.

This closes the vulnerability for two reasons the naive-sounding "it only calls existing methods anyway" objection misses:

1. **Scope creep over time.** `ReportRenderer` is not sealed against new methods. If a future developer adds any other public method (a debug helper, an admin-only reset, a method inherited from a base class or trait), it instantly becomes reachable through the macro field with no code change at the call site. The allowlist decouples "methods that exist" from "methods that are safe to expose as macros," so adding a new public method to the class no longer silently expands the attack surface.
2. **Explicit intent, not incidental restriction.** Before the fix, the only thing standing between a report author and arbitrary method dispatch was the current contents of the class, which is not a security boundary designers actually reason about. The allowlist is a single, auditable list that reviewers can check against the macro tokens the UI advertises, and it fails closed: an unrecognized token is rejected with an exception rather than silently invoking whatever happens to match.

Reject-and-throw was chosen over silently ignoring the bad value so misconfigured or tampered macro fields surface as errors during development and testing rather than failing open. If a broader set of legitimate macros is expected, keep the allowlist as the single source of truth and update it deliberately alongside any new `ReportRenderer` method that is meant to be end-user-invokable, rather than inferring permission from the class's method table.
