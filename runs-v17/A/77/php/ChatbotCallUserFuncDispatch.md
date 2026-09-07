## Verdict
CWE-77 confirmed. User-supplied input flows to `call_user_func_array()` without validation, allowing arbitrary PHP function invocation.

## Source
`$userMessage` parameter is user-controlled. Line 11-12 extract the command name into `$action` without allowlist validation. Line 19 passes `$action` directly to `call_user_func_array()`, which will call any function named in `$action`.

## Fix

### File: ChatbotCallUserFuncDispatch.php

```php
<?php
// Support-desk chat bot: visitors type slash-style commands in the widget
// and this endpoint dispatches them to the matching handler function.

// Whitelist of allowed chat commands and their handler functions
const ALLOWED_COMMANDS = [
    'status' => 'handleStatus',
    'help' => 'handleHelp',
    'info' => 'handleInfo',
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

    // Validate action against whitelist before dispatching
    if (!isset(ALLOWED_COMMANDS[$action])) {
        return "Unknown command: " . htmlspecialchars($action);
    }
    
    $handler = ALLOWED_COMMANDS[$action];
    $result = call_user_func_array($handler, $args);

    return is_string($result) ? $result : 'Command completed.';
}

function logChatCommand(string $sessionId, string $action, array $args): void
{
    error_log(sprintf('chatbot[%s] dispatch=%s args=%s', $sessionId, $action, implode(',', $args)));
}
```

## Explanation
The fix introduces a whitelist constant `ALLOWED_COMMANDS` that maps safe command names to their handler functions. Before dispatching (line 28-29), the code validates that `$action` exists as a key in the whitelist. Only when validation passes does it retrieve the handler function name from the map and pass it to `call_user_func_array()`. If the user supplies a command name not in the whitelist, the function returns an error message. This ensures only pre-approved functions can be called regardless of attacker input, eliminating the command injection vector.
