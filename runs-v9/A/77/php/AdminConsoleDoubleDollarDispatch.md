## Verdict

Confirmed. `handleAdminConsoleCommand()` takes the raw `action` POST parameter and uses it as a PHP variable-variable to invoke a function by name (`$$cmd()`). PHP's dynamic call syntax does not restrict the callee to the two intended handlers (`clearCache`, `purgeSessions`) - any name that resolves to a callable in scope, including PHP built-in functions such as `system`, `exec`, `shell_exec`, `passthru`, or `popen`, can be invoked this way. An attacker who controls the `action` field can execute arbitrary system commands, making this a command-injection sink even though no shell string is built directly.

## Source

`$_POST['action']` in `handleAdminConsoleCommand()` (line 14), trimmed but otherwise unvalidated before reaching the dynamic dispatch on line 20.

## Fix

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

    static $allowedCommands = [
        'clearCache'    => 'clearCache',
        'purgeSessions' => 'purgeSessions',
    ];

    if (!array_key_exists($cmd, $allowedCommands)) {
        return 'Unknown command';
    }

    $handler = $allowedCommands[$cmd];
    $result = $handler();

    return $result;
}
```

## Explanation

The root problem is that `$$cmd()` lets attacker-supplied text choose *which function runs*, not just its arguments. PHP will happily call `system`, `exec`, `passthru`, `shell_exec`, or any other name that resolves to a callable - there is no built-in restriction to functions the developer intended to expose. Blacklisting dangerous names or validating the input as "alphanumeric only" does not close this: it still permits calling any other in-scope function, including ones added later, and misses namespaced or class-static callables.

The fix replaces dynamic dispatch with an explicit allowlist: a fixed array mapping each supported command word to the specific function it may invoke. The lookup rejects anything not present in the map before any call happens, so the set of reachable functions is fixed at code-review time rather than derived from user input at runtime. This is the standard remediation for "user input selects a function/command name" - always resolve through a static, developer-controlled mapping rather than through language features (variable variables, `call_user_func` with a raw string, `${}` interpolation) that turn a string into code execution.

When extending this pattern to real admin consoles with many commands, keep the allowlist as the single source of truth for what is dispatchable, and add an authorization check on the handler (verify the caller has the admin role) alongside the input validation, since restricting *which* function can run does not by itself restrict *who* can trigger it.
