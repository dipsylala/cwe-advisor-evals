## Verdict

**CONFIRMED:** CWE-77 command injection via variable function invocation.

## Source

Line 14: untrusted input from `$_POST['action']` is retrieved and trimmed but not validated against an allowlist.

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

    // Allowlist of known command verbs mapped to their handler functions.
    $allowlist = [
        'clear-cache' => 'clearCache',
        'purge-sessions' => 'purgeSessions',
    ];

    // Validate the command verb against the allowlist.
    if (!isset($allowlist[$cmd])) {
        return 'Unknown command';
    }

    // Retrieve the handler function name from the allowlist.
    $handlerName = $allowlist[$cmd];

    // Invoke only the allowlisted handler via variable function.
    $result = $handlerName();

    return $result;
}
```

## Explanation

The vulnerability on line 20 used variable function invocation (`$$cmd()`) to directly dispatch to a function based on untrusted user input. An attacker could supply any function name available in the global scope and have it executed.

The fix introduces an explicit allowlist array that maps recognized command verbs to their corresponding handler function names. The command verb is validated against this allowlist before any dispatch occurs. Only after confirming the verb exists in the allowlist does the code proceed to invoke the handler. This prevents an attacker from invoking arbitrary functions.

The allowlist pattern is the primary defence for custom command interpreters in PHP: it breaks the untrusted-input-to-dispatch chain by requiring a specific lookup through a fixed whitelist before any function is invoked.

## Behaviour changes

- Unknown commands now return `'Unknown command'` instead of attempting to execute a non-existent function (which would produce a fatal error).
- Only the two registered handlers (`clearCache` and `purgeSessions`) can be invoked, regardless of what input is supplied.
- The input must match a key in the allowlist exactly; no partial matches or fallthrough execution is possible.
