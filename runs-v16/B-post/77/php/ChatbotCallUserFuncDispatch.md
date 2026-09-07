## Verdict

Exploitable. The user-supplied command verb flows directly from `$userMessage` through `$action` to `call_user_func_array()` without validation, allowing invocation of any callable function.

## Source

`$userMessage` parameter passed to `botReplyToUser()` at line 5 - attacker-controlled input from the chat widget.

## Fix

**Vulnerable code (line 11-19):**

```php
    $parts = explode(' ', substr($userMessage, 1), 2);
    $action = $parts[0];
    $rawArgs = $parts[1] ?? '';
    $args = $rawArgs === '' ? [] : explode(',', $rawArgs);

    logChatCommand($sessionId, $action, $args);

    // SAST FINDING: CWE-77 Command Injection at line 19
    $result = call_user_func_array($action, $args);
```

**Fixed code:**

```php
    // Define allowlist of recognized commands mapped to handler functions
    const COMMAND_HANDLERS = [
        'help' => 'handleHelp',
        'status' => 'handleStatus',
        'info' => 'handleInfo',
    ];

    $parts = explode(' ', substr($userMessage, 1), 2);
    $action = $parts[0];
    $rawArgs = $parts[1] ?? '';
    $args = $rawArgs === '' ? [] : explode(',', $rawArgs);

    logChatCommand($sessionId, $action, $args);

    // Look up action in allowlist; only dispatch if found
    if (!isset(COMMAND_HANDLERS[$action])) {
        return "Unknown command: " . htmlspecialchars($action);
    }

    $handler = COMMAND_HANDLERS[$action];
    $result = call_user_func_array($handler, $args);
```

Handler functions must be defined for each allowlisted command:

```php
function handleHelp(string $topic = 'general'): string {
    return "Help for $topic";
}

function handleStatus(): string {
    return "Status: online";
}

function handleInfo(): string {
    return "Bot info";
}
```

## Explanation

The fix closes the injection by replacing untrusted dynamic dispatch with allowlist-based lookup. Instead of passing `$action` (derived directly from user input) to `call_user_func_array()`, the code now:

1. Validates that `$action` exists as a key in the `COMMAND_HANDLERS` allowlist
2. Retrieves only the corresponding handler function name from the allowlist
3. Passes the allowlist-selected handler name to `call_user_func_array()`, not the original input

An attacker cannot invoke arbitrary functions because only the functions explicitly listed in `COMMAND_HANDLERS` can execute. An attempt to call an unlisted verb (such as `/phpinfo` or `/system` or `Class::method`) is rejected with an error message.

## Behaviour changes

- **New defensive behaviour**: Unknown commands now return an error message ("Unknown command: ...") instead of attempting execution. Previously, any callable function name could be dispatched.
- **Rejection of malformed input**: Commands not in the allowlist are explicitly rejected before reaching `call_user_func_array()`.
- **Handler invocation**: Handlers are now invoked by name from a fixed, server-controlled mapping, not by name derived from user input. Developers control which handlers exist and are invokable; users cannot add new ones.
- **Logging unchanged**: The `logChatCommand()` call still receives the original `$action` and `$args`, so the chat log preserves what the user attempted (useful for audit and debugging).

None of these changes break the existing contract: legitimate recognized commands still execute their handlers, arguments are still passed through, and the return value handling (converting non-string results to "Command completed.") remains identical.

