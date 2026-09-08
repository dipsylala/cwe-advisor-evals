## Verdict

Confirmed. `call_user_func_array($action, $args)` dispatches on a command verb taken directly from the attacker-controlled chat message, with no allowlist or validation before the call.

## Source

`botReplyToUser($sessionId, $userMessage)` - `$userMessage` is the raw text a chat-widget visitor typed. It is split on the first space: everything before the space becomes `$action`, everything after becomes `$rawArgs` (further split on `,` into `$args`). Neither `$action` nor the elements of `$args` are checked against any known set of values before use.

## Fix

### File: ChatbotCallUserFuncDispatch.php

```php
<?php
// Support-desk chat bot: visitors type slash-style commands in the widget
// and this endpoint dispatches them to the matching handler function.

/**
 * Allowlist of recognised chatbot command verbs. Only a handler listed
 * here can ever run - the user-supplied verb is looked up in this map
 * and never dispatched directly.
 */
const CHAT_COMMAND_HANDLERS = [
    'help'   => 'chatCmdHelp',
    'status' => 'chatCmdStatus',
    'hours'  => 'chatCmdHours',
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

    if (!array_key_exists($action, CHAT_COMMAND_HANDLERS)) {
        return "Sorry, I didn't understand that.";
    }

    $handler = CHAT_COMMAND_HANDLERS[$action];
    $result = call_user_func_array($handler, [$args]);

    return is_string($result) ? $result : 'Command completed.';
}

function logChatCommand(string $sessionId, string $action, array $args): void
{
    error_log(sprintf('chatbot[%s] dispatch=%s args=%s', $sessionId, $action, implode(',', $args)));
}

function chatCmdHelp(array $args): string
{
    return 'Available commands: /help, /status, /hours';
}

function chatCmdStatus(array $args): string
{
    return 'All systems operational.';
}

function chatCmdHours(array $args): string
{
    return 'Support hours: Mon-Fri 9am-5pm.';
}
```

## Explanation

The vulnerable line let the visitor's own text pick which PHP function, static method, or `__call()`-backed method got invoked - `call_user_func_array()` accepts not just plain function names but `"Class::method"` and other callable-string forms, so a message like `/exec` or `/phpinfo` (or any reachable internal function) would run it with attacker-supplied arguments. The fix adds a fixed allowlist (`CHAT_COMMAND_HANDLERS`) mapping known, exact command verbs to hardcoded handler names, and looks the incoming verb up with `array_key_exists()` - an exact match, no partial matching or case-folding. Only the handler string resolved from that lookup ever reaches `call_user_func_array()`; the original `$action` value is used solely as an allowlist key and never passed to dispatch. An unrecognised verb, whatever it is, falls through to the same "didn't understand" reply used for non-command messages, so no attacker-chosen string can select code to run.

## Behaviour changes

- Any command verb not in `{help, status, hours}` now returns "Sorry, I didn't understand that." instead of being dispatched. Previously an unmatched verb would either raise an uncaught `Error` (PHP 8+, since `call_user_func_array()` requires a valid callable) or, on older PHP, emit a warning and return `null` (silently reported back as "Command completed."). The three allowlisted verbs are illustrative placeholders for whatever commands the real chatbot supports elsewhere in the codebase; the allowlist should be extended with the application's actual command set, not with anything derived from `$action` at runtime.
- Handler functions are called with the parsed `$args` array as a single parameter (`chatCmdHelp(array $args)`) rather than being called with `$args` spread as positional parameters. The original code never invoked any real handler (any function it reached was a repurposed unrelated one, since dispatch was unrestricted), so no existing handler signature is broken by this choice; it keeps argument parsing/validation local to each handler.
- Logging (`logChatCommand`) still runs for every message, including rejected/unrecognised verbs, preserving the existing audit trail and satisfying the guidance to log rejected commands.
