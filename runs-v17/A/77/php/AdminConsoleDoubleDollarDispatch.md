## Verdict

CONFIRMED. Line 20 uses unconstrained variable function calls (`$$cmd()`) dispatched from user input, allowing invocation of arbitrary PHP functions. Remediation replaces the variable function call with an explicit allowlist-based dispatch.

## Source

```php
function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
    $result = $$cmd();

    return $result;
}
```

The vulnerability on line 20: `$$cmd()` performs an unconstrained function call based on `$_POST['action']`. An attacker can supply any function name to invoke arbitrary PHP functionality.

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

    // Dispatch only to explicitly allowed commands
    switch ($cmd) {
        case 'clearCache':
            $result = clearCache();
            break;
        case 'purgeSessions':
            $result = purgeSessions();
            break;
        default:
            $result = 'Unknown command';
            break;
    }

    return $result;
}
```

## Explanation

The fix replaces the unconstrained variable function call with an explicit `switch` statement that only permits calls to two hardcoded functions: `clearCache()` and `purgeSessions()`. Any command name not in this list is rejected with 'Unknown command'.

This approach:
- Eliminates variable function calls that depend on user input
- Makes the set of allowed commands visible and auditable
- Prevents invocation of any PHP function not explicitly listed
- Rejects unknown commands rather than attempting to invoke them

The allowlist is enforced at the point of dispatch, so even if `$cmd` contains a valid PHP function name that was not intended to be exposed (e.g., `phpinfo`, `exec`, `system`), the switch statement will not execute it.

