## Verdict

CONFIRMED. Line 20 uses PHP's variable variable syntax (`$$cmd()`) to dynamically invoke a function based on untrusted user input from `$_POST['action']`. This permits an attacker to invoke any available function in the PHP scope, enabling arbitrary code execution.

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

The vulnerability is on line 20: `$result = $$cmd();` interprets the user-supplied command string as a function name and invokes it without restriction.

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

    // Map of allowed commands to their handler functions
    $allowedCommands = [
        'clearCache' => 'clearCache',
        'purgeSessions' => 'purgeSessions',
    ];

    if (!isset($allowedCommands[$cmd])) {
        return 'Unknown command';
    }

    $functionName = $allowedCommands[$cmd];
    $result = $functionName();

    return $result;
}
```

## Explanation

The fix replaces the dangerous variable variable syntax with an explicit allowlist of permitted commands. Only commands present in the `$allowedCommands` array are allowed to execute. This prevents an attacker from invoking arbitrary functions by injecting unexpected values into the `action` parameter.

The remediation follows the principle of allowing only known-safe operations: the developer explicitly maps each permitted command name to its corresponding function, and the handler rejects any command not in this whitelist. This approach is safe even if new PHP functions or user-defined functions become available in the scope, because only mapped commands can be invoked.
