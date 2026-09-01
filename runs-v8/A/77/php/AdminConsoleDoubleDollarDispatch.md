## Verdict
Confirmed CWE-77. The variable variables construct `$$cmd()` uses unsanitized user input to dynamically invoke a function without allowlisting or validation.

## Source
`$_POST['action']` (line 14) flows to the function name resolver in `$$cmd()` (line 20). The input is trimmed but never validated against a set of permitted command names.

## Fix
Replace the dynamic dispatch with an explicit allowlist:

```php
function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    $allowedCommands = [
        'clearCache' => 'clearCache',
        'purgeSessions' => 'purgeSessions',
    ];

    if (!isset($allowedCommands[$cmd])) {
        return 'Unknown command';
    }

    $result = call_user_func($allowedCommands[$cmd]);

    return $result;
}
```

Or use a switch statement for the same effect:

```php
function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    switch ($cmd) {
        case 'clearCache':
            $result = clearCache();
            break;
        case 'purgeSessions':
            $result = purgeSessions();
            break;
        default:
            return 'Unknown command';
    }

    return $result;
}
```

## Explanation
Variable variables (`$$cmd()`) allow an attacker to invoke any callable in scope by controlling the POST parameter. While only two functions are defined here, an attacker could invoke built-in PHP functions or any other callable accessible in the execution environment, leading to command execution or other harmful operations.

An explicit allowlist (array mapping or switch statement) restricts execution to only the intended admin commands. This prevents injection of arbitrary function calls and is the standard pattern for dynamic dispatch in PHP when input-driven behavior is required.
