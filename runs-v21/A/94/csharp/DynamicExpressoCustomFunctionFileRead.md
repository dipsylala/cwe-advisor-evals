## Verdict

The code is vulnerable to code injection via the `Eval()` method (line 14) and arbitrary file read through the unvalidated `configKey` parameter in `LookupRate` (line 19).

## Source

```
E:/Github/cwe-advisor/evals/cases/94/csharp/DynamicExpressoCustomFunctionFileRead/DiscountRuleEvaluator.cs:14
```

The sink is `interpreter.Eval(rule)`, which evaluates untrusted user input as code. An attacker can inject arbitrary expressions. Additionally, the custom function `lookupRate()` calls `File.ReadAllText()` with an unvalidated path, enabling arbitrary file reads.

## Fix

### File: DiscountRuleEvaluator.cs

```csharp
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using DynamicExpresso;

namespace Cases.CodeInjection;

public sealed class DiscountRuleEvaluator
{
    private readonly Dictionary<string, decimal> _rateConfigs;
    private static readonly Regex SafeRuleExpression = new Regex(
        @"^[\s0-9a-zA-Z_\.\,\(\)\+\-\*/%""']+$",
        RegexOptions.Compiled
    );

    public DiscountRuleEvaluator(Dictionary<string, decimal> rateConfigs)
    {
        _rateConfigs = rateConfigs ?? throw new ArgumentNullException(nameof(rateConfigs));
    }

    public object? Evaluate(string rule, decimal orderTotal)
    {
        if (string.IsNullOrWhiteSpace(rule) || !SafeRuleExpression.IsMatch(rule))
        {
            throw new InvalidOperationException("Rule contains invalid characters");
        }

        var interpreter = new Interpreter();
        interpreter.SetVariable("orderTotal", orderTotal);
        interpreter.SetFunction("lookupRate", (System.Func<string, decimal>)LookupRate);

        return interpreter.Eval(rule);
    }

    private decimal LookupRate(string configKey)
    {
        if (string.IsNullOrWhiteSpace(configKey) || !_rateConfigs.TryGetValue(configKey, out var rate))
        {
            throw new InvalidOperationException($"Invalid configuration key: '{configKey}'");
        }
        return rate;
    }
}
```

## Explanation

The fix addresses CWE-94 code injection and eliminates arbitrary file access through two key changes:

1. **Input validation for rule parameter**: A whitelist regex validates the rule string before `Eval()` execution, rejecting any input containing characters not in the allowed set. This prevents attackers from injecting arbitrary code expressions while still allowing legitimate mathematical operations and function calls.

2. **Whitelist-based configuration lookup**: Replace `File.ReadAllText()` with a constructor-injected `Dictionary<string, decimal>` that serves as an allowlist. The `LookupRate` function validates that `configKey` exists in this dictionary before returning the rate. This eliminates both arbitrary file access and path traversal attacks.

The validation occurs before the Eval sink, establishing a control point that restricts what code can be evaluated to only safe, intended expressions. This prevents attackers from executing injected commands while maintaining the intended functionality for legitimate discount rule evaluation.
