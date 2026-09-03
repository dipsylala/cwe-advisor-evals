## Verdict

Confirmed. Line 19 passes unsanitized user input directly to `call_user_func_array()` as the function name parameter, allowing arbitrary function dispatch.

## Source

The `$action` variable derives from the user-supplied `$userMessage` via `explode()` at line 11. This value flows directly into `call_user_func_array($action, $args)` at line 19 with no validation that `$action` names an approved command handler.

## Fix

Establish a whitelist of allowed command handlers and validate `$action` against it before dispatch:

```php
<?php
// Support-desk chat bot: visitors type slash-style commands in the widget
// and this endpoint dispatches them to the matching handler function.

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

    // Define whitelist of allowed command handlers
    $allowedHandlers = [
        'help' => 'handleHelp',
        'status' => 'handleStatus',
        'reset' => 'handleReset',
    ];

    // Validate action against whitelist
    if (!isset($allowedHandlers[$action])) {
        return "Unknown command: /$action";
    }

    $result = call_user_func_array($allowedHandlers[$action], $args);

    return is_string($result) ? $result : 'Command completed.';
}

function logChatCommand(string $sessionId, string $action, array $args): void
{
    error_log(sprintf('chatbot[%s] dispatch=%s args=%s', $sessionId, $action, implode(',', $args)));
}
```

## Explanation

CWE-77 command injection via `call_user_func_array()` occurs when user input determines which function executes. Without an allowlist, an attacker can invoke system functions (e.g. `exec()`, `system()`, `passthru()`) or application functions unintended for dispatch.

The fix defines `$allowedHandlers` mapping public command names to their handler functions. Only commands present in the whitelist are dispatched; all others are rejected. This enforces that dispatch reaches only functions the developer explicitly approved for external invocation.

The allowlist must be maintained as new bot commands are added—adding a handler function is not sufficient without also registering it in `$allowedHandlers`.
