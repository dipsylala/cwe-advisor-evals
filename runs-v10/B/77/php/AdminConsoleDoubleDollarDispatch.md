## Verdict

Exploitable. The variable-variable dispatch on line 20 allows untrusted input to invoke any function in the PHP runtime, including built-in functions with side effects.

## Source

Line 14: `$cmd = trim($_POST['action'] ?? '');`

User-controlled input from `$_POST['action']` is passed directly to the dispatch sink with only whitespace trimming, no validation.

## Fix

Replace the dangerous variable-variable dispatch with an allowlist array that maps known command verbs to handler functions. Only functions in the allowlist may be invoked.

```php
<?php
// Admin console: staff type a short command word into a text box and this
// handler dispatches it to the matching internal function.

function clearCache() {
    return 'cache cleared';
}

function purgeSessions() {
    return 'sessions purged';
}

function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    // Allowlist mapping command verbs to handler functions
    $allowedCommands = [
        'cache' => 'clearCache',
        'sessions' => 'purgeSessions',
    ];

    // Reject commands not in the allowlist
    if (!isset($allowedCommands[$cmd])) {
        return 'Unknown command';
    }

    // Dispatch only to the allowlisted handler
    $handler = $allowedCommands[$cmd];
    $result = $handler();

    return $result;
}
```

## Explanation

The fix replaces the variable-variable dispatch `$$cmd()` with an explicit allowlist. The input `$cmd` is no longer used to determine which function to call. Instead, it is looked up in a fixed `$allowedCommands` array that maps known command verbs to their handler functions. Only functions present in that array can be invoked. An unknown command is rejected with an error message. This prevents an attacker from calling arbitrary PHP functions or user-defined functions outside the intended set.

The allowlist pattern is the primary defence documented in the CWE-77 PHP guidance for custom command interpreters.

## Behaviour changes

**Before:** Any function name passed in the `action` parameter is invoked without restriction.

**After:** Only command verbs explicitly mapped in the `$allowedCommands` array (`cache` and `sessions`) are recognized. All other input is rejected and returns the error message "Unknown command".

**Test cases that should now fail safely:**
- `action=phpinfo` → returns "Unknown command" instead of executing `phpinfo()`
- `action=system` → returns "Unknown command" instead of executing `system()`
- `action=clearCache` → returns "Unknown command" (exact function name not in allowlist; must use mapped verb `cache`)
- `action=cache` → executes `clearCache()` and returns "cache cleared" (unchanged)
- `action=sessions` → executes `purgeSessions()` and returns "sessions purged" (unchanged)
