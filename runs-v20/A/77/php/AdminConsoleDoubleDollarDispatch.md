## Verdict

Confirmed. `handleAdminConsoleCommand()` takes the raw `action` POST field and uses PHP's
variable-variable/dynamic-call syntax `$$cmd()` to invoke a function whose name is the
attacker-supplied string. Because PHP will call *any* callable name reachable in scope, this is
not limited to `clearCache()`/`purgeSessions()` - an attacker who submits `action=phpinfo`,
`action=system`, `action=exec`, `action=assert`, `action=ini_set`, or the name of any other
reachable function can trigger arbitrary function invocation, up to and including OS command
execution if a command-execution function is reachable in the same request lifecycle (directly,
via an autoloaded class, or via a function defined elsewhere in the codebase).

## Source

- `$_POST['action']` (line 14), trimmed into `$cmd`, then used unvalidated as a callable name at
  the sink on line 20.

## Fix

### File: AdminConsoleDoubleDollarDispatch.php

```php
<?php
// Admin console: staff type a short command word into a text box and this
// handler dispatches it to the matching internal function.

function clearCache() {
    return 'cache cleared';
}

function purgeSessions() {
    return 'sessions purged';
}

function handleAdminConsoleCommand() {
    $cmd = trim($_POST['action'] ?? '');
    if ($cmd === '') {
        return 'No command supplied';
    }

    // Fixed: dispatch through an explicit allowlist of known command names
    // mapped to fixed callables, instead of calling a name built from
    // attacker-controlled input.
    $allowedCommands = [
        'clearCache' => 'clearCache',
        'purgeSessions' => 'purgeSessions',
    ];

    if (!array_key_exists($cmd, $allowedCommands)) {
        return 'Unknown command';
    }

    $result = call_user_func($allowedCommands[$cmd]);

    return $result;
}
```

## Explanation

The vulnerability is not the *specific* command-execution API being reachable today - it is that
`$$cmd()` turns any user-supplied string into a function call target, so the attack surface is
every function name in scope rather than the two intended admin actions. The fix removes the
dynamic-name-to-callable path entirely: `$cmd` is looked up in a fixed, hardcoded array whose
keys are the only command names the console supports and whose values are the exact callables to
invoke. If `$cmd` is not one of those literal keys, the request is rejected with "Unknown
command" before any call happens.

This is a safer allowlist than a regex or character-class check on `$cmd` would be, because it
constrains the value to a closed set of *known-safe callables* rather than merely a shape of
string - no string satisfying some pattern can ever reach `call_user_func()` unless it is one of
the two names the admin console was built to support. Adding a new console command is a matter of
adding a new key/value pair to `$allowedCommands`, which keeps the dispatch table (not
freeform user input) as the single source of truth for what is callable.
