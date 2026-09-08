## Verdict
CONFIRMED

## Source
Line 19 of ChatbotCallUserFuncDispatch.php:
```php
$result = call_user_func_array($action, $args);
```

The `$action` variable is derived from user input in the `$userMessage` parameter. A user can craft a message like `/system whoami` to invoke arbitrary PHP functions. The `call_user_func_array()` function executes any callable with attacker-controlled name and arguments, enabling direct command injection attacks.

## Fix

### File: ChatbotCallUserFuncDispatch.php

```php
<?php
// Support-desk chat bot: visitors type slash-style commands in the widget
// and this endpoint dispatches them to the matching handler function.

// Whitelist of allowed bot commands mapped to handler functions
const ALLOWED_BOT_COMMANDS = [
    'help' => 'botHelp',
    'status' => 'botStatus',
    'reset' => 'botReset',
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

    // Whitelist check: only allow registered bot commands
    if (!isset(ALLOWED_BOT_COMMANDS[$action])) {
        return "Unknown command: $action";
    }

    $result = call_user_func_array(ALLOWED_BOT_COMMANDS[$action], $args);

    return is_string($result) ? $result : 'Command completed.';
}

function logChatCommand(string $sessionId, string $action, array $args): void
{
    error_log(sprintf('chatbot[%s] dispatch=%s args=%s', $sessionId, $action, implode(',', $args)));
}
```

## Explanation
The vulnerability arises from allowing user input to directly determine which function is called. By using a whitelist constant `ALLOWED_BOT_COMMANDS`, the fix restricts callable functions to only those explicitly registered by the developer. The lookup checks if the requested action exists in the whitelist before invoking it; if not, an error message is returned. This prevents attackers from calling dangerous functions like `system`, `exec`, `eval`, or any other sensitive callable. The whitelist approach is the primary defense for command injection via function dispatch: it ensures that only intended handler functions can be invoked, regardless of what an attacker supplies in user input.
