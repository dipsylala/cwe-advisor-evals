## Verdict

Confirmed. Line 14 directly evaluates the unsanitized `rule` parameter as code via `interpreter.Eval()`, enabling arbitrary code execution. Additionally, the registered `LookupRate` function (line 19) allows file I/O based on attacker-controlled input, compounding the injection risk.

## Source

The `rule` string parameter (line 7) originates from an external caller with no validation. It is passed to `interpreter.Eval()` (line 14) which interprets it as executable code. The `LookupRate` function registered with the interpreter (line 11) permits file reads using the attacker-supplied `configKey` parameter, allowing information disclosure or denial of service.

## Fix

```csharp
using DynamicExpresso;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Cases.CodeInjection;

public sealed class DiscountRuleEvaluator
{
    // Allowlist of permitted configuration keys for rate lookup
    private static readonly HashSet<string> ValidConfigKeys = new()
    {
        "standard_rate",
        "bulk_rate",
        "vip_rate"
    };

    // Regex pattern to permit only arithmetic expressions with variables and numbers
    private static readonly Regex SafeRulePattern = new Regex(
        @"^[\d\(\)\+\-\*/\.\s]+$|^[\d\(\)\+\-\*/\.\s]*orderTotal[\d\(\)\+\-\*/\.\s]*$",
        RegexOptions.Compiled
    );

    public object? Evaluate(string rule, decimal orderTotal)
    {
        // Validate rule against allowlist before evaluation
        if (string.IsNullOrEmpty(rule) || !SafeRulePattern.IsMatch(rule))
        {
            throw new ArgumentException("Rule expression contains invalid characters or syntax", nameof(rule));
        }

        var interpreter = new Interpreter();
        interpreter.SetVariable("orderTotal", orderTotal);
        
        // Register only safe operations; remove direct file I/O function
        // interpreter.SetFunction("lookupRate", ...) is removed to prevent file access
        
        return interpreter.Eval(rule);
    }

    // If rate lookup is required elsewhere, use a separate method with strict validation
    public static decimal LookupRate(string configKey)
    {
        // Whitelist validation: only allow predefined configuration keys
        if (!ValidConfigKeys.Contains(configKey))
        {
            throw new ArgumentException($"Unknown configuration key: {configKey}", nameof(configKey));
        }

        return decimal.Parse(System.IO.File.ReadAllText(configKey));
    }
}
```

## Explanation

The vulnerability arises from evaluating untrusted user input as code. DynamicExpresso's `Eval()` method is a code interpreter—passing unsanitized input to it enables an attacker to execute arbitrary expressions.

The fix employs two layers of defense:

1. **Allowlist validation on the rule parameter**: Before evaluation, the rule is validated against a regex pattern that permits only arithmetic operations (`+`, `-`, `*`, `/`, parentheses, digits, and the predefined `orderTotal` variable). Any rule containing function calls, property access, or other dangerous syntax is rejected.

2. **Removal of dangerous function registration**: The `interpreter.SetFunction("lookupRate", ...)` call is removed from the evaluate path, eliminating the attacker's ability to invoke file I/O through injected code.

3. **Separation of concerns**: If rate lookup functionality is required, it is moved to a separate method with its own strict whitelist validation on the `configKey` parameter, limiting file access to predefined configuration keys only.

This prevents both direct code injection and the secondary file-I/O escalation path.
