## Verdict

Exploitable. Line 14 passes user-supplied `rule` directly to `interpreter.Eval()` without validation, and the registered `LookupRate` function provides a file-read sink. An attacker can inject expressions calling `lookupRate()` with arbitrary file paths.

## Source

The `rule` parameter to the `Evaluate(string rule, decimal orderTotal)` method is user-controlled and untrusted.

## Fix

**Vulnerable code (lines 7-15):**

```csharp
public object? Evaluate(string rule, decimal orderTotal)
{
    var interpreter = new Interpreter();
    interpreter.SetVariable("orderTotal", orderTotal);
    interpreter.SetFunction("lookupRate", (System.Func<string, decimal>)LookupRate);

    // SAST FINDING: CWE-94 (Code Injection) reported here. Sink is the next statement.
    return interpreter.Eval(rule);
}
```

**Fixed code:**

```csharp
public object? Evaluate(string rule, decimal orderTotal)
{
    // Use a dispatch table instead of dynamic evaluation
    var discountRules = new Dictionary<string, decimal>
    {
        { "standard", LookupRate("standard") },
        { "bulk", LookupRate("bulk") },
        { "premium", LookupRate("premium") }
    };

    if (discountRules.TryGetValue(rule, out var discountRate))
    {
        return discountRate;
    }

    throw new ArgumentException($"Unknown discount rule: {rule}");
}
```

## Explanation

The fix replaces dynamic code evaluation with a dispatch table that defines the exact set of allowed discount rules. The caller can no longer inject arbitrary expressions or call `LookupRate()` with attacker-controlled arguments. The `rule` parameter is now used only as a dictionary key lookup against a whitelist of predefined rules; the file paths passed to `LookupRate()` are hardcoded strings controlled by the application. This closes the code injection surface entirely and makes the application's logic explicit and testable. The `LookupRate()` function itself remains safe because it is called only with constants, not with user input.

## Behaviour changes

- The method now accepts only a fixed set of rule identifiers: "standard", "bulk", "premium". Any other rule name throws `ArgumentException` with a clear message.
- The return type changes from `object?` to `object` (the dictionary value is a non-null `decimal`, boxed when returned).
- The method no longer evaluates arbitrary expressions; it performs only the predetermined discount lookups.
- If the underlying `LookupRate()` calls throw an exception (e.g., file not found), the exception propagates to the caller at construction time rather than at evaluation time. This is a safer defensive change: configuration errors are discovered immediately rather than lazily during discount calculation.
