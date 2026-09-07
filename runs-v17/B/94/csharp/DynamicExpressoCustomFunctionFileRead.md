## Verdict

Exploitable. Line 14 passes untrusted user input (`rule` parameter) directly to `interpreter.Eval()`, which executes it as arbitrary C# code in the DynamicExpresso evaluator context. The registered custom function `LookupRate` on line 11 receives file path arguments from within the evaluated expression and reads files using `System.IO.File.ReadAllText(configKey)`, enabling attackers to extract arbitrary file contents via expressions like `lookupRate("/etc/passwd")`.

## Source

The `rule` parameter (line 7) receives untrusted user input and flows directly to the code injection sink at line 14. The `LookupRate` function registered on line 11 is itself a secondary sink because it accepts user-controlled file paths from evaluated expressions and performs file I/O.

## Fix

### File: DiscountRuleEvaluator.cs

```csharp
using DynamicExpresso;

namespace Cases.CodeInjection;

public sealed class DiscountRuleEvaluator
{
    private static readonly Dictionary<string, decimal> RateConfiguration = new()
    {
        { "standard", 0.10m },
        { "premium", 0.15m },
        { "vip", 0.20m }
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
        if (RateConfiguration.TryGetValue(configKey, out var rate))
        {
            return rate;
        }

        throw new ArgumentException($"Unknown rate configuration key: {configKey}");
    }
}
```

## Explanation

The CWE-94 guidance states that custom functions registered with `SetFunction()` become attack surface when they perform dangerous operations: "each registered delegate is a hole opened deliberately, so review any that takes a `Type`, reflects on a string argument, or reaches files, processes or the network as a sink in its own right." The original `LookupRate` function accepts arbitrary file path strings and executes `System.IO.File.ReadAllText()` on them, creating a direct file-disclosure vulnerability regardless of input validation on the `rule` parameter. The fix replaces file I/O with a lookup in a predefined, server-controlled `RateConfiguration` dictionary. When an evaluated expression calls `lookupRate(userSuppliedKey)`, it now retrieves only whitelisted rates and throws `ArgumentException` for unknown keys rather than reading files. This eliminates the file-access sink while preserving the custom function's intended behavior for valid rate lookups. The C# guidance explicitly names `DynamicExpresso.Interpreter.Eval()` as a taint sink and recommends restricting it to only explicitly registered variables and functions with safe implementations.

## Behaviour changes

The `LookupRate` function's behavior changes from accepting arbitrary file paths to accepting only keys from `RateConfiguration`: `"standard"`, `"premium"`, and `"vip"` (case-sensitive). Any expression that calls `lookupRate()` with a key outside this set now throws `ArgumentException` instead of performing file I/O. This is a breaking change for code that relied on reading rates from files, but that behavior was itself the vulnerability. No other functionality is altered; the `Evaluate()` method's return contract, the `orderTotal` variable binding, and the expression evaluation mechanism remain unchanged.
