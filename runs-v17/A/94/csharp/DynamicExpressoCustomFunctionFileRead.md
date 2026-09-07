## Verdict
**CONFIRMED** - CWE-94 Code Injection via unsanitized `rule` parameter passed directly to `interpreter.Eval()` on line 14.

## Source
**File:** DiscountRuleEvaluator.cs  
**Line:** 14  
**Vulnerable Code:** `return interpreter.Eval(rule);`

The `rule` parameter is user-controlled input accepted directly from the method parameter and passed unsanitized to DynamicExpresso's `Eval()` method, allowing arbitrary code execution within the expression evaluator context.

## Fix
### File: DiscountRuleEvaluator.cs
```csharp
using DynamicExpresso;
using System.Text.RegularExpressions;

namespace Cases.CodeInjection;

public sealed class DiscountRuleEvaluator
{
    private static readonly Regex AllowedRulePattern = new(
        @"^[a-zA-Z0-9_()\s,+\-*/<>=!&|.]+$",
        RegexOptions.Compiled
    );

    public object? Evaluate(string rule, decimal orderTotal)
    {
        // Validate rule to prevent code injection
        ValidateRule(rule);

        var interpreter = new Interpreter();
        interpreter.SetVariable("orderTotal", orderTotal);
        interpreter.SetFunction("lookupRate", (System.Func<string, decimal>)LookupRate);

        return interpreter.Eval(rule);
    }

    private static void ValidateRule(string rule)
    {
        if (string.IsNullOrWhiteSpace(rule))
        {
            throw new ArgumentException("Rule cannot be null or empty", nameof(rule));
        }

        // Check length to prevent abuse
        if (rule.Length > 1000)
        {
            throw new ArgumentException("Rule is too long", nameof(rule));
        }

        // Deny known dangerous patterns that enable code injection
        if (rule.Contains("typeof", StringComparison.OrdinalIgnoreCase) ||
            rule.Contains("new ", StringComparison.OrdinalIgnoreCase) ||
            rule.Contains("System.", StringComparison.OrdinalIgnoreCase) ||
            rule.Contains("File.", StringComparison.OrdinalIgnoreCase) ||
            rule.Contains("Directory.", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Rule contains invalid patterns", nameof(rule));
        }

        // Ensure rule only contains allowed characters (identifiers, operators, parentheses)
        if (!AllowedRulePattern.IsMatch(rule))
        {
            throw new ArgumentException("Rule contains invalid characters", nameof(rule));
        }
    }

    private static decimal LookupRate(string configKey)
    {
        return decimal.Parse(System.IO.File.ReadAllText(configKey));
    }
}
```

## Explanation
The vulnerability stems from passing untrusted user input directly to `Eval()`, which can execute arbitrary expressions. The remediation adds input validation through two mechanisms:

1. **Blacklist dangerous patterns**: Blocks keywords like `typeof`, `new`, and namespace prefixes (`System.`, `File.`, `Directory.`) that could escape the sandboxed evaluator context.

2. **Whitelist allowed characters**: A compiled regex ensures the rule contains only legitimate expression syntax (identifiers, operators, parentheses, comparison operators). This prevents injection of arbitrary language constructs.

3. **Length check**: Caps rule length at 1000 characters to prevent degenerate cases.

These checks execute before `Eval()` is called, preventing injection of arbitrary code while still allowing legitimate discount rule expressions like `orderTotal > 100` or `lookupRate("discount_tier")`.
