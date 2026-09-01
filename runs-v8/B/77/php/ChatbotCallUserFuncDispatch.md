## Verdict

The finding is confirmed. Line 19 passes untrusted user input directly to `call_user_func_array()` without validation, allowing an attacker to invoke arbitrary functions.

## Source

User input flows from `$userMessage` parameter → split into parts (line 11) → `$action` assigned from `$parts[0]` (line 12) → passed to `call_user_func_array($action, $args)` (line 19) without validation.

## Fix

Replace the dynamic dispatch with an explicit allowlist lookup:

```php
<?php
// Support-desk chat bot: visitors type slash-style commands in the widget
// and this endpoint dispatches them to the matching handler function.

// Explicit allowlist mapping command verbs to handler function names
const COMMAND_HANDLERS = [
    'help' => 'handleHelp',
    'status' => 'handleStatus',
    'reset' => 'handleReset',
];

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

    // Validate command verb against allowlist
    if (!isset(COMMAND_HANDLERS[$action])) {
        logChatCommand($sessionId, 'UNKNOWN_COMMAND', [$action]);
        return "Unknown command: $action";
    }

    // Dispatch using allowlist-selected handler, not untrusted input
    $handler = COMMAND_HANDLERS[$action];
    $result = call_user_func_array($handler, $args);

    return is_string($result) ? $result : 'Command completed.';
}

function logChatCommand(string $sessionId, string $action, array $args): void
{
    error_log(sprintf('chatbot[%s] dispatch=%s args=%s', $sessionId, $action, implode(',', $args)));
}
```

## Explanation

The fix introduces an explicit allowlist constant `COMMAND_HANDLERS` that maps known command verbs to their corresponding handler function names. Before dispatching, the code now validates that `$action` exists as a key in this allowlist. Only when validation succeeds does the code retrieve the allowlist-selected handler name and pass it to `call_user_func_array()`. This breaks the direct connection between untrusted input and dynamic dispatch: an attacker cannot invoke functions outside the allowlist, regardless of what command string they submit.

The allowlist must be kept in application code, not derived from user input or configuration. Each command verb maps to exactly one hardcoded handler function. Unknown commands are rejected with an error message, and rejected attempts are logged for monitoring.

## Behaviour changes

- **New validation**: Commands not present in `COMMAND_HANDLERS` are now rejected with an error message. Previously, any function name could be called.
- **Logging change**: Rejected unknown commands are logged with action `UNKNOWN_COMMAND` for audit/monitoring purposes.
- **Return value preserved**: Legitimate commands return the same result as before; only attackers' attempts to invoke unregistered functions change behavior (now rejected instead of executed).
- **Input parsing unchanged**: Argument parsing and structure remain the same; only the dispatch target validation is added.
