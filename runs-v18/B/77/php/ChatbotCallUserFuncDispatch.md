## Verdict

Exploitable

## Source

`$userMessage` parameter, untrusted user input passed to the chat bot endpoint. An attacker can inject any PHP function name via the command verb (first word after the `/` prefix).

## Fix

### File: ChatbotCallUserFuncDispatch.php

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

    // Allowlist of known commands mapped to handler functions
    $allowedCommands = [
        'help' => 'handleHelp',
        'status' => 'handleStatus',
    ];

    // Validate that the action is in the allowlist before dispatch
    if (!isset($allowedCommands[$action])) {
        return "Unknown command: " . htmlspecialchars($action);
    }

    // Dispatch only to the allowlisted handler, breaking taint after validation
    $handler = $allowedCommands[$action];
    $result = call_user_func_array($handler, $args);

    return is_string($result) ? $result : 'Command completed.';
}

function logChatCommand(string $sessionId, string $action, array $args): void
{
    error_log(sprintf('chatbot[%s] dispatch=%s args=%s', $sessionId, $action, implode(',', $args)));
}
?>
```

## Explanation

The original code passed `$action` (derived directly from user input) to `call_user_func_array()`, allowing an attacker to invoke any PHP function by submitting `/shell_exec` or similar function names. The fix implements the primary defence prescribed by CWE-77 PHP guidance: an explicit allowlist mapping known command verbs to specific handler functions. The `$action` variable is validated against this allowlist before any dispatch occurs. If the action is not in the allowlist, the function returns an error message. Only after validation passes is a reference to the allowlisted handler retrieved and passed to `call_user_func_array()`, breaking the taint chain. This ensures that only functions explicitly added to the allowlist can ever be invoked, regardless of what an attacker submits in the chat message.

## Behaviour changes

**Added allowlist validation**: The fix introduces a new `$allowedCommands` array mapping command verbs to handler functions. This is a required defence mechanism and does not alter the sink contract - it still returns the result of the dispatched handler.

**Added error return**: When an unknown command is submitted, the function now returns an error message instead of attempting dispatch. This is a breaking change for malformed input (which previously would have thrown a fatal error attempting to call a non-existent function), but this is the intended safe-by-default behavior.

**Handler parameter signature assumption**: The fix assumes handler functions accept variadic string arguments (`string ...$args`), which matches the argument array structure already present in the code. If handlers have different signatures, they must be updated to accept arguments as an array or the call changed to pass them differently - however, this is application-specific and does not affect the security fix itself.

No other behaviour changes. The arguments are parsed and handled identically to the original code; only the dispatch target is now validated.
