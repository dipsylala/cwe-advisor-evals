## Verdict

Code injection vulnerability: untrusted `rule` parameter is executed as DynamicExpresso code (line 14), and the exposed `LookupRate` function permits arbitrary file reads through its `configKey` parameter.

## Source

- Line 14: `return interpreter.Eval(rule);` - passes untrusted `rule` directly to dynamic evaluator
- Line 11: `interpreter.SetFunction("lookupRate", ...LookupRate)` - exposes function that reads files based on user-controlled input
- Line 19: `System.IO.File.ReadAllText(configKey)` - file read sink, where `configKey` originates from expression passed via `rule`

## Fix

Replace dynamic code evaluation with a static approach using predefined rate lookups:

```csharp
using System;
using System.Collections.Generic;

namespace Cases.CodeInjection;

public sealed class DiscountRuleEvaluator
{
    private static readonly Dictionary<string, decimal> RateCache = new()
    {
        { "standard", 0.10m },
        { "premium", 0.15m },
        { "vip", 0.20m }
    };

    public object? Evaluate(string rule, decimal orderTotal)
    {
        // Validate rule against strict allowlist of permitted operations
        if (!IsValidRule(rule))
        {
            throw new ArgumentException("Invalid discount rule expression", nameof(rule));
        }

        // Apply predefined discount logic based on rule
        return rule switch
        {
            "standard" => EvaluateStandardDiscount(orderTotal),
            "premium" => EvaluatePremiumDiscount(orderTotal),
            "vip" => EvaluateVipDiscount(orderTotal),
            _ => throw new ArgumentException($"Unknown rule: {rule}", nameof(rule))
        };
    }

    private static bool IsValidRule(string rule)
    {
        // Only permit known rule identifiers
        return rule is "standard" or "premium" or "vip";
    }

    private static decimal EvaluateStandardDiscount(decimal orderTotal)
    {
        return orderTotal > 100 ? LookupRate("standard") : 0m;
    }

    private static decimal EvaluatePremiumDiscount(decimal orderTotal)
    {
        return orderTotal > 50 ? LookupRate("premium") : 0m;
    }

    private static decimal EvaluateVipDiscount(decimal orderTotal)
    {
        return LookupRate("vip");
    }

    private static decimal LookupRate(string configKey)
    {
        // configKey is now constrained to known values by the switch statement above
        if (RateCache.TryGetValue(configKey, out var rate))
        {
            return rate;
        }

        throw new InvalidOperationException($"Rate configuration not found: {configKey}");
    }
}
```

## Explanation

The fix eliminates dynamic code evaluation entirely. Instead of passing untrusted input to DynamicExpresso's `Eval()`:

1. **Eliminates the expression evaluator**: Removes `DynamicExpresso.Interpreter` and its associated attack surface. No dynamic code evaluation means no code injection vulnerability.

2. **Validates rule names against an allowlist**: The `Evaluate()` method validates that `rule` is one of the predefined rule identifiers before processing it. Invalid rules raise an exception immediately.

3. **Constrains file access**: Replaces the parameterized `LookupRate(configKey)` with direct calls to a predefined lookup table. The `configKey` parameter is no longer exposed to attacker control - it is hardcoded by the discount logic, not derived from user input.

4. **Uses a lookup table for configuration**: Rate values are defined in `RateCache` rather than read from files, preventing arbitrary file reads. This also improves performance and testability.

The static dispatch pattern (switch statement) is applied in each evaluation method, making the permitted discount rules explicit and auditable.

## Behaviour changes

- **Stricter input validation**: Only recognized rule names ("standard", "premium", "vip") are accepted; other values throw `ArgumentException`.
- **No more file I/O**: Rate lookups are now in-memory; no `System.IO.File.ReadAllText()` calls occur.
- **Predictable, deterministic behavior**: Discount calculations are now statically defined rather than dynamically generated, improving security and testability.
- **Exception on unknown rules**: Calling `Evaluate()` with a rule outside the allowlist raises an exception instead of executing arbitrary code.
