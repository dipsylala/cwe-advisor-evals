## Verdict

VULNERABLE. The `rule` parameter at line 14 is supplied untrusted (from the method caller), flows directly to `interpreter.Eval(rule)`, and is dynamically evaluated as C# expression code. The registered `LookupRate` function (line 11) wraps `System.IO.File.ReadAllText()` at line 19, making file reading accessible from within evaluated expressions. An attacker can inject expressions like `lookupRate("../../../../etc/passwd")` to read arbitrary files.

## Source

The untrusted source is the `rule` parameter to `Evaluate()`. It has no validation before reaching the sink `interpreter.Eval(rule)` at line 14.

## Fix

Replace dynamic code evaluation with a static dictionary-based dispatch of predefined discount rules. Load configuration at application startup, not at runtime from user input. Remove the file-reading function from the expression surface entirely.

```csharp
using System;
using System.Collections.Generic;

namespace Cases.CodeInjection;

public sealed class DiscountRuleEvaluator
{
    private readonly Dictionary<string, decimal> _discountRates;

    public DiscountRuleEvaluator(Dictionary<string, decimal> discountRates)
    {
        _discountRates = discountRates ?? throw new ArgumentNullException(nameof(discountRates));
    }

    public object? Evaluate(string rule, decimal orderTotal)
    {
        if (string.IsNullOrEmpty(rule))
        {
            throw new ArgumentException("Rule cannot be null or empty.", nameof(rule));
        }

        if (!_discountRates.TryGetValue(rule, out var rate))
        {
            throw new ArgumentException($"Unknown discount rule: {rule}");
        }

        return orderTotal * rate;
    }
}
```

Configuration is provided at instantiation:

```csharp
var discountRates = new Dictionary<string, decimal>
{
    ["smallOrder"] = 0.05m,
    ["mediumOrder"] = 0.10m,
    ["largeOrder"] = 0.15m,
};

var evaluator = new DiscountRuleEvaluator(discountRates);
var result = evaluator.Evaluate("smallOrder", 49.99m); // Returns 2.4995
```

## Explanation

The fix eliminates the code injection vulnerability by removing dynamic code evaluation entirely. Instead of compiling and executing arbitrary expressions via `DynamicExpresso.Interpreter.Eval()`, discount rules are now a predefined set of identifiers mapped to calculated rates. The user-supplied `rule` parameter is validated as a dictionary key using `TryGetValue()` rather than executed as code. The `LookupRate` function and all file access are removed from the expression surface. Configuration is loaded at application startup (through the constructor), not dynamically at runtime based on user input, ensuring no file paths can be injected.

## Behaviour changes

- **Eliminated attack surface**: No dynamic code evaluation; the `rule` parameter is now a whitelist key lookup rather than executable code.
- **Configuration timing**: Discount rates are loaded once at application startup (constructor), not computed at request time from untrusted input.
- **Removed file access**: The `LookupRate()` function and `System.IO.File.ReadAllText()` calls are gone; file reading cannot occur during discount evaluation.
- **Stricter validation**: Invalid rule names throw an exception immediately instead of attempting evaluation (fail-closed).
- **Functional change**: The caller must now supply predefined rule identifiers rather than arbitrary expressions; callers cannot dynamically construct discount logic at runtime.
