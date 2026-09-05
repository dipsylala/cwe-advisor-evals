## Verdict

Exploitable. Untrusted user input (`$userMessage`) reaches the dynamic dispatch sink (`call_user_func_array()`) with no validation, allowing an attacker to invoke any function by supplying `/functionName` as the command.

## Source

`$userMessage` parameter to `botReplyToUser()` at line 5. User input begins at line 7 (check for `/` prefix), is parsed at line 11 (`explode()`), and the first word is extracted at line 12 (`$action = $parts[0]`).

## Fix

**Vulnerable code (lines 11–19):**
```php
$parts = explode(' ', substr($userMessage, 1), 2);
$action = $parts[0];
$rawArgs = $parts[1] ?? '';
$args = $rawArgs === '' ? [] : explode(',', $rawArgs);

logChatCommand($sessionId, $action, $args);

// SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
$result = call_user_func_array($action, $args);
```

**Fixed code:**
```php
// Define a fixed allowlist of valid commands and their handler functions.
// Map each recognized command verb to a specific handler function.
$COMMAND_HANDLERS = [
    'help' => 'handleHelp',
    'status' => 'handleStatus',
    'close' => 'handleClose',
];

$parts = explode(' ', substr($userMessage, 1), 2);
$action = $parts[0];
$rawArgs = $parts[1] ?? '';
$args = $rawArgs === '' ? [] : explode(',', $rawArgs);

logChatCommand($sessionId, $action, $args);

// Validate that the action is in the allowlist before dispatching.
if (!isset($COMMAND_HANDLERS[$action])) {
    return "Unknown command.";
}

// Use only the allowlisted handler, never the original untrusted $action.
$handler = $COMMAND_HANDLERS[$action];
$result = call_user_func_array($handler, $args);
```

## Explanation

The fix replaces dynamic dispatch on user-supplied input with an explicit allowlist. Instead of calling `call_user_func_array($action, $args)` where `$action` comes directly from the user, the code now validates that `$action` matches a key in the `$COMMAND_HANDLERS` allowlist, then retrieves the corresponding handler function name from that trusted map. Only after validation does the handler reference (not the original user input) reach `call_user_func_array()`. This prevents an attacker from invoking arbitrary functions; they can only trigger the handlers explicitly defined in the allowlist.

## Behaviour changes

- **Added allowlist definition**: `$COMMAND_HANDLERS` array is introduced (deployment-time or source configuration).
- **Added validation check**: An `isset($COMMAND_HANDLERS[$action])` guard is added before dispatch. Unrecognized commands now return "Unknown command." instead of attempting dispatch.
- **Changed dispatch target**: The first argument to `call_user_func_array()` changes from the untrusted `$action` to the allowlist-validated `$handler`. The handler names and function signatures remain the same, so existing handler implementations do not change; only the invocation path is secured.
- **Error handling**: Mistyped or unknown commands are now rejected explicitly rather than raising a `ValueError` or `Warning` at dispatch time.
