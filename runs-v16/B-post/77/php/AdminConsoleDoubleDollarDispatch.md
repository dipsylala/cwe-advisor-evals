## Verdict

Exploitable. The user input directly controls which function is called via variable-variable dispatch without any allowlist or validation.

## Source

`$_POST['action']` at line 14, trimmed and stored in `$cmd`.

## Fix

**Vulnerable code (line 20):**

```php
$result = $$cmd();
```

**Fixed code:**

```php
// Allowlist of valid command verbs mapped to handlers
$allowedCommands = [
    'clearCache' => 'clearCache',
    'purgeSessions' => 'purgeSessions',
];

// Reject any command not in the allowlist
if (!isset($allowedCommands[$cmd])) {
    return 'Unknown command';
}

// Dispatch to the allowlist-selected handler, not the user input
$handler = $allowedCommands[$cmd];
$result = $handler();
```

## Explanation

The original code invoked a function by using the untrusted user input directly as a variable variable (`$$cmd()`), allowing an attacker to call any function in scope. The fixed code replaces this with an explicit allowlist array that maps known-safe command verbs to their corresponding handler functions. The input is validated against this allowlist before dispatch, and only the allowlist-selected handler reference is invoked, ensuring that only `clearCache` and `purgeSessions` can ever be called. This follows the primary defence pattern for CWE-77 in PHP: mapping recognised command verbs to specific, hardcoded handlers.

## Behaviour changes

- Added allowlist validation that rejects unknown commands with 'Unknown command' return value instead of attempting to invoke them.
- Changed dispatch mechanism from variable-variable invocation (`$$cmd()`) to explicit handler function call via allowlist lookup (`$handler()`).
- Attacker can no longer invoke arbitrary functions; only whitelisted handlers will execute.

