## Verdict

Exploitable.

## Source

The `rule` parameter of the `Evaluate` method (line 7) receives untrusted input. An attacker controls the expression text that will be evaluated by DynamicExpresso.

## Fix

### File: DiscountRuleEvaluator.cs

```csharp
using DynamicExpresso;
using System.Collections.Generic;

namespace Cases.CodeInjection;

public sealed class DiscountRuleEvaluator
{
    private static readonly Dictionary<string, decimal> DiscountRates = new()
    {
        { "standard", 0.10m },
        { "premium", 0.20m },
        { "enterprise", 0.30m }
    };

    public object? Evaluate(string rule, decimal orderTotal)
    {
        var interpreter = new Interpreter();
        interpreter.SetVariable("orderTotal", orderTotal);
        interpreter.SetFunction("lookupRate", (System.Func<string, decimal>)LookupRate);

        return interpreter.Eval(rule);
    }

    private static decimal LookupRate(string configKey)
    {
        if (DiscountRates.TryGetValue(configKey, out var rate))
        {
            return rate;
        }
        throw new KeyNotFoundException($"Discount rate '{configKey}' not found.");
    }
}
```

## Explanation

The original code passed untrusted user input (`rule`) directly to `interpreter.Eval()` and registered a custom function `LookupRate` that performs arbitrary file I/O via `System.IO.File.ReadAllText(configKey)`. An attacker could craft an expression like `lookupRate("/etc/passwd")` to read any file accessible to the application. The fix eliminates the file I/O sink by replacing it with a lookup table of predefined, safe configuration values. The custom function now only retrieves values from the `DiscountRates` dictionary and throws a `KeyNotFoundException` if an unknown key is requested, preventing any attempt to access arbitrary files. The `lookupRate` custom function remains available for legitimate discount rule expressions (e.g., `lookupRate("premium")`), but no longer exposes file system access.

## Behaviour changes

- Added `using System.Collections.Generic;` import to support the Dictionary type.
- Added a static `DiscountRates` dictionary field containing predefined discount rate mappings.
- Changed `LookupRate` implementation from file I/O to dictionary lookup with key validation.
- `LookupRate` now throws `KeyNotFoundException` instead of allowing arbitrary file paths to be read.
- All file I/O capability is removed from functions accessible via the expression evaluator.

