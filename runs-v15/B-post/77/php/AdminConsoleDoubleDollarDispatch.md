## Verdict

exploitable

## Source

`$_POST['action']` (untrusted user input from HTTP POST request)

## Fix

**Vulnerable code:**
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

**Fixed code:**
```php
function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    // Define the allowlist of command verbs mapped to their handler functions
    $commandHandlers = [
        'clearCache'    => 'clearCache',
        'purgeSessions' => 'purgeSessions',
    ];

    // Look up the command in the allowlist; reject if not found
    if (!isset($commandHandlers[$cmd])) {
        return 'Unknown command';
    }

    // Invoke only the allowlist-selected handler
    $result = $commandHandlers[$cmd]();

    return $result;
}
```

## Explanation

The vulnerability arises from variable-variable function invocation (`$$cmd()`) on untrusted user input, which allows an attacker to invoke any function in the PHP runtime by providing its name in the POST parameter. The fix replaces this with an explicit allowlist array that maps known command verbs to their handler functions. User input is now used only for array lookup, not for dynamic dispatch. Only callable strings from the allowlist can be invoked, and unknown commands are rejected with a clear error message.

## Behaviour changes

The function now returns "Unknown command" instead of attempting to execute commands not in the allowlist. This is a security restriction and intended behavior change - it prevents invocation of unintended functions while preserving the legitimate command-handling functionality for enumerated commands.
