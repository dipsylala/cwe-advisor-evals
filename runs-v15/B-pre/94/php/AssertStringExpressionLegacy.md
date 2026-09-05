## Verdict

exploitable

## Source

`$requestData['account_type']` (line 16) from untrusted JSON request body decoded at line 38, passed to `checkPremiumAccess()` at line 44 and assigned to `$accountType` at line 16.

## Fix

**Before:**
```php
$rule = "'" . $accountType . "' == 'premium'";
assert($rule);
```

**After:**
```php
assert($accountType === 'premium');
```

## Explanation

In PHP 7.x, `assert()` with a string argument executes that string as PHP code, making it an eval-style code injection sink. The original code constructs a string expression from user-supplied `$accountType` and passes it to `assert()`, allowing an attacker to inject arbitrary PHP code. For example, submitting `account_type: " . system('id') . "` would result in code execution. The fix replaces the string-based assertion with a direct boolean assertion using the strict comparison operator, which evaluates immediately to a true/false value without interpreting the input as executable code. In PHP 8.0+, string assertions became inert (treated as always-truthy non-empty strings) and stopped evaluating, so on that platform this finding does not exploit; on PHP 7.x targets where this code runs, the fix closes the execution path entirely.

## Behaviour changes

In PHP 7.x: Changed from evaluating a string expression as PHP code to performing a direct boolean comparison. The assertion message changes from the constructed string `"'" . $accountType . "' == 'premium'"` to a boolean result, which will affect how assertion failures are logged or reported.

In PHP 8.0+: Functionally equivalent to the original (which already did not execute), but explicitly correct and does not rely on the version-dependent behavior that stopped string assertions from evaluating.
