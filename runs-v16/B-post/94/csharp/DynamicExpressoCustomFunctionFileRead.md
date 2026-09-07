## Verdict

Exploitable. An attacker can pass arbitrary DynamicExpresso expressions in the `rule` parameter to line 14, and call the registered `lookupRate` function with attacker-controlled file paths, reading any file the application process can access. This is code injection via unrestricted dynamic evaluation combined with a file-read sink in a registered custom function.

## Source

User-supplied `rule` parameter passed to `Evaluate()` method (line 7), reaching the code evaluation sink at line 14 without validation. Secondary attack surface: the `lookupRate` custom function (line 11) accepts untrusted file paths and passes them to `File.ReadAllText()` (line 19).

## Fix

**Vulnerable code (lines 5-21):**
```csharp
public sealed class DiscountRuleEvaluator
{
    public object? Evaluate(string rule, decimal orderTotal)
    {
        var interpreter = new Interpreter();
        interpreter.SetVariable("orderTotal", orderTotal);
        interpreter.SetFunction("lookupRate", (System.Func<string, decimal>)LookupRate);

        // SAST FINDING: CWE-94 (Code Injection) reported here. Sink is the next statement.
        return interpreter.Eval(rule);
    }

    private static decimal LookupRate(string configKey)
    {
        return decimal.Parse(System.IO.File.ReadAllText(configKey));
    }
}
```

**Fixed code:**
```csharp
using System.Collections.Generic;
using DynamicExpresso;

namespace Cases.CodeInjection;

public sealed class DiscountRuleEvaluator
{
    // Predefined discount rules: map rule names to their logic
    private static readonly Dictionary<string, Func<decimal, decimal>> AllowedRules = new()
    {
        { "standard", orderTotal => orderTotal > 100 ? 0.1m : 0m },
        { "premium", orderTotal => orderTotal > 50 ? 0.15m : 0.05m },
        { "clearance", orderTotal => orderTotal > 200 ? 0.25m : 0m }
    };

    // Predefined config values: map config keys to allowed values
    private static readonly Dictionary<string, decimal> AllowedRates = new()
    {
        { "base_rate", 0.05m },
        { "premium_rate", 0.15m },
        { "clearance_rate", 0.25m }
    };

    public object? Evaluate(string rule, decimal orderTotal)
    {
        // Validate rule against allowlist of permitted rule names
        if (!AllowedRules.TryGetValue(rule, out var ruleFunc))
        {
            throw new ArgumentException($"Unknown discount rule: {rule}. Allowed values: {string.Join(", ", AllowedRules.Keys)}");
        }

        // Execute only the predefined rule logic, eliminating code injection
        return ruleFunc(orderTotal);
    }

    private static decimal LookupRate(string configKey)
    {
        // Validate configKey against allowlist of permitted keys
        if (!AllowedRates.TryGetValue(configKey, out var rate))
        {
            throw new ArgumentException($"Unknown config key: {configKey}. Allowed keys: {string.Join(", ", AllowedRates.Keys)}");
        }

        // Return only whitelisted config values; no file access
        return rate;
    }
}
```

## Explanation

The fix eliminates code injection by removing the unrestricted dynamic code evaluation entirely. Instead of passing untrusted `rule` input to `interpreter.Eval()`, the fixed code validates the rule parameter against a static dictionary of allowed rule names (`AllowedRules`), and executes only the predefined logic for that rule. This transforms the operation from "evaluate arbitrary code in a user-supplied string" to "apply one of a fixed set of predefined functions selected by name."

The secondary vulnerability in `LookupRate` is addressed in parallel: instead of accepting arbitrary file paths and reading them with `File.ReadAllText()`, the fixed version validates the `configKey` parameter against a static whitelist (`AllowedRates`) and returns only hardcoded safe values. This eliminates the file-read sink. Together, these changes close both the code-injection and the file-read attack surfaces.

The fix preserves the original method signature and return type, so existing callers of `Evaluate()` continue to work unchanged.

## Behaviour changes

- **Dictionary lookups replace dynamic evaluation**: The `Evaluate()` method now performs dictionary lookups instead of calling `Interpreter.Eval()`. This is a breaking change to the attack surface but preserves the functional contract for callers - they still pass a rule name and get back a computed discount. Callers expecting to be able to pass arbitrary expressions will receive an `ArgumentException` instead.
- **Config value whitelisting in `LookupRate`**: The method now returns values from a predefined map instead of reading files. This is a breaking change for any caller expecting file I/O, but the method signature remains compatible - it still takes a `string` and returns a `decimal`.
- **Added `AllowedRules` and `AllowedRates` dictionaries**: These encode the set of permitted operations. They are static and immutable, so extending the set of allowed rules or rates requires a code change and recompilation rather than accepting configuration from input.
- **ArgumentException on unknown rule or key**: The original code would raise an exception from the interpreter (e.g., `UnknownIdentifierException` if a rule name did not exist); the fixed code throws `ArgumentException` with a descriptive message listing allowed values. Exception type changed, but exception throwing on invalid input is preserved.
