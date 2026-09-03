## Verdict
Exploitable

## Source
Untrusted input from `$_POST['action']` (line 14) flows directly into variable function invocation at line 20.

## Fix

**Vulnerable code:**
```php
function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    // SAST FINDING: CWE-77 - variable function invocation on untrusted input
    $result = $$cmd();

    return $result;
}
```

**Fixed code:**
```php
function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    // Allowlist of known commands mapped to their handlers
    $handlers = [
        'clearCache' => 'clearCache',
        'purgeSessions' => 'purgeSessions',
    ];

    // Reject any command not in the allowlist
    if (!isset($handlers[$cmd])) {
        return 'Unknown command';
    }

    // Dispatch only to the allowlist-validated handler reference
    $handler = $handlers[$cmd];
    $result = $handler();

    return $result;
}
```

## Explanation

The vulnerability allows an attacker to invoke any PHP function by sending arbitrary function names via `$_POST['action']`. The variable function syntax `$$cmd()` directly dispatches to whatever function name the user supplies. The fix implements the PHP-specific safe pattern: an explicit allowlist array mapping known command verbs to their handler function names. After validation against the allowlist, dispatch occurs only through the trusted handler reference retrieved from the allowlist, not from the untrusted input. This ensures only `clearCache` and `purgeSessions` can ever be invoked, regardless of what an attacker sends.

## Behaviour changes

None. The fix preserves the original behavior: the same two functions are callable via the same command verbs, and the same return values flow back to the caller. The only change is adding a validation gate that rejects unknown commands with "Unknown command" instead of throwing a PHP error.
