## Verdict

CWE-77 confirmed. The code passes user-controlled input directly to `call_user_func_array()`, allowing arbitrary function invocation including dangerous built-in functions like `system()`, `exec()`, `passthru()`, and `eval()`.

## Source

Line 19: `$result = call_user_func_array($action, $args);`

The `$action` variable originates from parsing the user's `$userMessage` parameter at lines 11-12. An attacker can craft input like `/system ls -la /etc/passwd` to invoke `system()` with arbitrary shell commands, or `/eval phpinfo()` to execute arbitrary PHP code.

## Fix

Replace the dynamic function invocation with an explicit allowlist:

```php
function botReplyToUser(string $sessionId, string $userMessage): string
{
    if (strpos($userMessage, '/') !== 0) {
        return "Sorry, I didn't understand that.";
    }

    $parts = explode(' ', substr($userMessage, 1), 2);
    $action = $parts[0];
    $rawArgs = $parts[1] ?? '';
    $args = $rawArgs === '' ? [] : explode(',', $rawArgs);

    logChatCommand($sessionId, $action, $args);

    // Map of allowed command handlers
    $handlers = [
        'help' => 'handleHelpCommand',
        'status' => 'handleStatusCommand',
        'reset' => 'handleResetCommand',
    ];

    if (!isset($handlers[$action])) {
        return "Unknown command: {$action}";
    }

    $handlerName = $handlers[$action];
    $result = call_user_func_array($handlerName, $args);

    return is_string($result) ? $result : 'Command completed.';
}
```

## Explanation

The fix replaces dynamic function name resolution with an explicit allowlist mapping. Only command names explicitly present in the `$handlers` array can be dispatched, preventing attackers from invoking arbitrary PHP functions. The handler function names are hardcoded strings, not user-supplied, so they cannot be manipulated. This maintains the dispatcher pattern while eliminating the command injection vector by ensuring only application-defined handlers are callable, regardless of what `$action` value an attacker provides.
