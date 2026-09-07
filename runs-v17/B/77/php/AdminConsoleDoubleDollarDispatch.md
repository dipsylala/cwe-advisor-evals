## Verdict

The finding is valid. Variable-variable function dispatch on untrusted user input (`$$cmd()`) allows an attacker to invoke arbitrary functions in the PHP application's scope. The input `$_POST['action']` is only trimmed for whitespace, leaving all function names accessible.

## Source

**File:** AdminConsoleDoubleDollarDispatch.php, line 20

**Input path:** `$_POST['action']` (line 14) → trimmed to `$cmd` → used in `$$cmd()` dispatch

**Vulnerable pattern:** Dynamic function invocation via variable-variable syntax on untrusted input without validation.

## Fix

### File: AdminConsoleDoubleDollarDispatch.php

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

    // Allowlist of supported commands mapped to their handler functions
    $commandHandlers = [
        'clearCache' => 'clearCache',
        'purgeSessions' => 'purgeSessions',
    ];

    // Look up the command in the allowlist
    if (!isset($commandHandlers[$cmd])) {
        return 'Unknown command';
    }

    // Call only the allowlisted handler
    $handler = $commandHandlers[$cmd];
    $result = $handler();

    return $result;
}
```

## Explanation

The fix replaces the unsafe variable-variable dispatch (`$$cmd()`) with an explicit allowlist lookup. The untrusted `$cmd` input is now used only as a dictionary key against a hardcoded map of recognized commands, preventing invocation of arbitrary functions. After the allowlist lookup succeeds, the selected handler function name (which comes from the allowlist, not from user input) is used for dispatch. This breaks the taint chain: user input can no longer determine which function runs—only the allowlist can.

The allowlist is defined as a simple associative array mapping command verbs to handler function names. The `isset()` check ensures the command exists in the allowlist before attempting invocation. Unknown commands are rejected with an error message instead of being passed to dispatch.

## Behaviour changes

- Unknown or unrecognized commands now return "Unknown command" instead of generating a fatal error (undefined function call).
- Only the two explicitly allowlisted commands (`clearCache`, `purgeSessions`) can be invoked. Any attempt to invoke other functions—including internal PHP functions, built-ins, or other user-defined functions—is blocked.
- The application's attack surface is reduced from "all functions in scope" to "only the two documented admin commands."
