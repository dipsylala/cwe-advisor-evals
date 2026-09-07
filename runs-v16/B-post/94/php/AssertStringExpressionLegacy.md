## Verdict

Exploitable

## Source

`$requestData['account_type']` at line 16 (untrusted JSON request body parameter, passed through line 20 into `$rule`)

## Fix

**Vulnerable code:**
```php
        $accountType = isset($requestData['account_type']) ? $requestData['account_type'] : 'basic';

        // Business rule is expressed as a string and evaluated with assert() so
        // the same rule text can be logged alongside the pass/fail result.
        $rule = "'" . $accountType . "' == 'premium'";

        // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
        assert($rule);
```

**Fixed code:**
```php
        $accountType = isset($requestData['account_type']) ? $requestData['account_type'] : 'basic';

        // Direct boolean check replaces string evaluation via assert()
        $isPremium = ($accountType === 'premium');
        assert($isPremium);
```

## Explanation

The vulnerability arises from using `assert()` with a dynamically constructed string in PHP 7.x, which evaluates that string as PHP code. An attacker controlling `$requestData['account_type']` can inject arbitrary PHP code. Replacing the string concatenation and string-based assertion with a direct boolean comparison (`$accountType === 'premium'`) eliminates the dynamic code evaluation. The assert now receives a boolean value instead of a code string, preventing injection. The comparison preserves the original business logic: confirming the account type is the string `'premium'`.

## Behaviour changes

**Logging impact**: The original code's comment references logging the rule text; the fixed code loses this capability since `$isPremium` is a boolean. If rule-text logging is required, add a separate logging statement before or after the assertion with the canonical rule text (not the constructed string), or remove the assertion and perform the check inline with explicit error handling.

**PHP version handling**: In PHP 8.0+, `assert()` with a string argument already stopped evaluating it as code (treats any non-empty string as truthy), so on current versions the original code is dead—it never tested the condition at all. The fixed code works identically across PHP 7.x and 8.x+, making the intent explicit and testable.

