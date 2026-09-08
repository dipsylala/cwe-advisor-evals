## Verdict

CWE-77 (Improper Neutralization of Special Elements used in a Command), exploitable. Confidence: high.

This is the bespoke command-interpreter form of CWE-77 called out explicitly in both the root and PHP guidance: the macro token is not passed to an OS shell (that would be CWE-78), it selects and invokes a method on `ReportRenderer` via PHP's variable-method-call syntax. No allowlist, verb validation, or use-scope restriction exists between the untrusted token and the dispatch call.

## Source

- **Source**: `$_POST['macro']` (`MacroDynamicMethodDispatch.php:16`) - a macro token from a report layout that a report owner edits via a "custom macro" UI field. Only an empty-string check (`$macro === ''`) is applied; the value is otherwise unvalidated and reaches the sink unchanged.
- **Sink**: `$renderer->$macro()` (`MacroDynamicMethodDispatch.php:23`) - PHP variable-method-call syntax, invoking whatever public method name the tainted string names on the `ReportRenderer` instance.
- **Sink contract**: all four current methods (`refresh`, `exportCsv`, `purgeCache`, `deleteReport`) are `void`, take no arguments, and return/discard nothing observable by the caller. `$renderer->$macro()` passes no arguments and its return value is unused, so the fix must not introduce arguments or start consuming a return value. On failure (`$macro` naming no public method), PHP throws an uncaught `Error` ("Call to undefined method"), which is fatal - today, any macro token that doesn't exactly match one of the four method names already crashes the request; there is no existing graceful-rejection path to preserve.
- **Exploitability**: because `ReportRenderer` declares no `__call()`/`__callStatic()` magic method, the attacker is currently limited to invoking one of the four declared public methods (or any public method inherited from a parent class, not shown here) by name - but the dispatch itself is unconstrained by design, so it becomes a full arbitrary-public-method-invocation primitive the moment the class gains a more sensitive method, a magic method, or a subclass. Findings of this shape are flagged and fixed at the dispatch site, not dismissed based on what the current method list happens to contain.

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

    // Allowlist mapping each recognised macro token to the renderer method
    // that implements it. Only the method name resolved from this lookup is
    // ever handed to dynamic dispatch - the raw token itself never reaches
    // the sink.
    $allowedMacros = [
        'refresh' => 'refresh',
        'exportCsv' => 'exportCsv',
        'purgeCache' => 'purgeCache',
        'deleteReport' => 'deleteReport',
    ];

    if (!array_key_exists($macro, $allowedMacros)) {
        // Unknown macro token: reject instead of dispatching arbitrary input.
        return;
    }

    $method = $allowedMacros[$macro];
    $renderer->$method();
}
```

## Explanation

The fix replaces unconstrained dynamic dispatch with an explicit allowlist: `$allowedMacros` maps each recognised macro token to the exact method name that implements it, `array_key_exists()` rejects any token that isn't one of the four known verbs, and the value handed to `$renderer->$method()` is the allowlist's own value, not the original `$_POST['macro']` string - so even if the lookup and the dispatch value happen to be textually identical today, the tainted variable itself never reaches the sink. This closes the weakness because the set of strings that can ever reach `$renderer->$method()` is now fixed at four literals defined in code, independent of what `ReportRenderer` declares or gains later (a `__call()` magic method, a new public method, a parent-class method) - the attacker's input can only select among those four outcomes, never name an arbitrary method.

**Verification**: `php -l` against the fixed file in a scratch location reported no syntax errors. Functional check (also in scratch, subclassing `ReportRenderer` with instrumented overrides) confirmed: a legitimate token (`exportCsv`) still dispatches to the correct method; an attacker-supplied non-verb string (`system("id")`) and an empty string both resolve to no method call and no error, where the original code either called an attacker-chosen method or (for any non-matching, non-empty string) threw a fatal `Error`.

## Behaviour changes

- **Unknown/malformed macro token now returns silently instead of throwing a fatal `Error`.** Previously, any `$macro` value that wasn't `''` and didn't exactly match one of the four public method names crashed the request with an uncaught `Error` ("Call to undefined method"). The fix reclassifies that case as a rejected/no-op macro (same early-return shape as the existing `$macro === ''` check) rather than a fatal error. This is a deliberate part of the remediation - the guidance's Remediation Steps direct rejecting an unrecognized command verb outright rather than letting it fall through - but it does mean a caller that was relying on the crash (e.g. to surface a malformed layout loudly) will instead see the macro silently skipped; if that visibility is wanted, add logging at the rejection point.
- No change to arguments passed to any method (none, before or after), no change to return-value handling (unused, before or after), and no change to behaviour for the four legitimate macro tokens or for the existing empty-string case.
