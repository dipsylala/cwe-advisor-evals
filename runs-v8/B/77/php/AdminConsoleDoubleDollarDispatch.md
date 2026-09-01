## Verdict

Confirmed. Line 20 uses variable-variable function invocation (`$$cmd()`) directly on untrusted input from `$_POST['action']`, allowing arbitrary function execution.

## Source

Line 14: `$_POST['action']` - user-supplied command verb, untrusted.

## Fix

**Vulnerable code (line 20):**
```php
$result = $$cmd();
```

**Fixed code:**
```php
// Allowlist of valid command handlers
$handlers = [
    'clearCache' => 'clearCache',
    'purgeSessions' => 'purgeSessions',
];

if (!isset($handlers[$cmd])) {
    return 'Unknown command';
}

$handler = $handlers[$cmd];
$result = $handler();
```

## Explanation

The fix replaces variable-variable dispatch with an explicit allowlist array that maps command verbs to their handler function names. After the lookup, only the allowlist-selected function name (`$handler`) is passed to invocation, breaking the taint path. This ensures only `clearCache` and `purgeSessions` can be invoked, preventing arbitrary function execution. The attack surface (passing function names like `system`, `eval`, or internal class methods) is eliminated because those names are not in the allowlist.

## Behaviour changes

Legitimate commands (`clearCache`, `purgeSessions`) return the same results as before. Unknown commands return 'Unknown command' instead of causing a PHP error when an undefined function is called. The function signatures and return values remain unchanged for valid commands.
