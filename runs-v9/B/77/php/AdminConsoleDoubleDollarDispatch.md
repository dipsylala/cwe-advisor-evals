## Verdict

exploitable (confidence: high)

- **cwe_id**: CWE-77 (Improper Neutralization of Special Elements used in a Command)
- **location**: `AdminConsoleDoubleDollarDispatch.php:20`
- **assumptions**: This is application-level command dispatch (a custom admin-console interpreter selecting an internal function by name), not OS shell execution, so `cwe/77/php` guidance applies directly rather than CWE-78.

## Source

`$_POST['action']` (HTTP request body parameter), read at line 14:

```
$cmd = trim($_POST['action'] ?? '');
```

The only check applied before the sink is an empty-string rejection (line 15-17). `$cmd` is otherwise unvalidated and unconstrained.

## Fix

Vulnerable code (line 13-23):

```php
function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    // SAST FINDING: CWE-77 reported here. Sink is the next statement.
    $result = $$cmd();

    return $result;
}
```

Fixed code:

```php
function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    switch ($cmd) {
        case 'clearCache':
            return clearCache();
        case 'purgeSessions':
            return purgeSessions();
        default:
            return 'Unknown command';
    }
}
```

## Explanation

The sink at line 20, `$$cmd()`, is PHP variable-variable dispatch: it invokes whatever zero-argument global function is named by the attacker-controlled string `$cmd`, with no restriction on which function that can be. Because PHP function calls resolve by name at call time and are case-insensitive, any global, zero-required-argument function reachable in this process's scope - not just `clearCache` and `purgeSessions` - can be invoked by an attacker who knows or guesses its name, which is the core of the weakness. The fix replaces the dynamic dispatch with a hardcoded `switch` that only ever calls one of the two intended handlers by their literal names; there is no longer any invocation path from user input to a function call. This is the primary defence the PHP CWE-77 guidance prescribes: map each recognised command verb to a specific, hardcoded handler via an explicit allowlist, and never let untrusted input choose which function is invoked directly. No argument parsing is added because neither handler takes arguments.

## Behaviour changes

- Command-verb matching is now case-sensitive (`===` via `switch`), where `$$cmd()` resolved case-insensitively (e.g. `CLEARCACHE` would previously have dispatched to `clearCache`). This is intentional: the guidance calls for exact-match allowlisting and explicitly flags casing as an attack vector to reject, not a convenience to preserve.
- An unrecognised command now returns the string `'Unknown command'` instead of the previous behaviour: calling an undefined function via `$$cmd()` throws an uncaught `Error` (fatal error). This is a deliberate part of the fix - the allowlist rejects unknown verbs by design - but it changes the response/error surface for malformed input from a crash to a handled string, which the caller should be aware of if it previously relied on catching that `Error`.
- No change to the behaviour or return values of `clearCache()` or `purgeSessions()` themselves, and no change to the empty-command handling at lines 15-17.
