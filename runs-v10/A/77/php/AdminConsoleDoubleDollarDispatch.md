## Verdict
Real vulnerability confirmed.

## Source
The vulnerability is a **variable variable attack** in `handleAdminConsoleCommand()` at line 20:

```php
$cmd = trim($_POST['action'] ?? '');
// ...
$result = $$cmd();
```

The `$cmd` value—directly from untrusted user input `$_POST['action']`—is used as a variable variable to call a function dynamically. An attacker can supply the name of any callable function (built-in or user-defined) to execute arbitrary code. For example, submitting `action=system&arg=id` or other dangerous payloads would invoke PHP's dangerous functions.

## Fix
Replace the variable variable call with a whitelist mapping that only permits intended functions:

```php
function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    // Whitelist of allowed commands
    $allowedCommands = [
        'clearCache' => 'clearCache',
        'purgeSessions' => 'purgeSessions',
    ];

    if (!isset($allowedCommands[$cmd])) {
        return 'Invalid command';
    }

    $functionName = $allowedCommands[$cmd];
    $result = $functionName();

    return $result;
}
```

## Explanation
Variable variables (`$$var`) combined with user input are inherently unsafe for function dispatch because they bypass all control flow analysis. An attacker can call any function in scope, including dangerous built-ins like `system()`, `exec()`, `shell_exec()`, `eval()`, or `assert()`.

The fix uses an explicit whitelist: user input is validated against a predefined dictionary of safe function names before dispatch occurs. The dispatch then calls only the approved function. This pattern—explicit mapping rather than dynamic construction—is the standard defence for command dispatch in any language (similar to switch statements or dispatch tables in C/C++). The whitelist approach is also more maintainable and enables auditing of which commands are available.
