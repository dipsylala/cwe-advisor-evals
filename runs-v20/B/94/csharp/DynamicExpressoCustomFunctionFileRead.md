## Verdict

Exploitable.

- **cwe_id**: CWE-94 (Improper Control of Generation of Code / Code Injection)
- **location**: `DiscountRuleEvaluator.cs`, line 14 (`interpreter.Eval(rule)`), reaching the registered custom function's sink at line 19
- **confidence**: high

## Source

`rule`, the `string` parameter of `DiscountRuleEvaluator.Evaluate(string rule, decimal orderTotal)`. This is the discount-rule expression text supplied to the evaluator; nothing in the file constrains its content before it reaches `interpreter.Eval(rule)`, and no caller is present in the case directory to show it being validated upstream, so it is treated as attacker-controlled expression text (e.g. a merchant- or customer-supplied discount formula).

## Fix

### File: DiscountRuleEvaluator.cs

```csharp
using System;
using System.Collections.Generic;
using DynamicExpresso;

namespace Cases.CodeInjection;

public sealed class DiscountRuleEvaluator
{
    // Allowlist mapping rate configuration keys to their trusted file paths.
    // The expression text can only select a key by name; the dictionary -
    // not the expression - decides which file actually gets read.
    private static readonly IReadOnlyDictionary<string, string> RateConfigFiles =
        new Dictionary<string, string>
        {
            ["standard"] = @"C:\config\rates\standard.txt",
            ["seasonal"] = @"C:\config\rates\seasonal.txt",
            ["clearance"] = @"C:\config\rates\clearance.txt",
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
        if (!RateConfigFiles.TryGetValue(configKey, out var path))
        {
            throw new ArgumentException($"Unknown rate configuration key: '{configKey}'", nameof(configKey));
        }

        return decimal.Parse(System.IO.File.ReadAllText(path));
    }
}
```

## Explanation

`DiscountRuleEvaluator` builds a `DynamicExpresso.Interpreter` with reflection left disabled and no `Reference()` calls, so `interpreter.Eval(rule)` cannot itself reach `System.IO`, `System.Diagnostics`, or any other .NET type directly - a bare interpreter carrying only `SetFunction`/`SetVariable` registrations is not, by itself, the hole. The hole is the registered function: `SetFunction("lookupRate", ...)` opens an identifier that `rule` can call with any string literal the expression author writes, and `LookupRate` passed that string straight into `System.IO.File.ReadAllText(configKey)`. Because `rule` is attacker-controlled, an expression such as `lookupRate("C:/secrets/appsettings.json")` (or a UNC/relative-traversal path) makes the evaluator read and return the contents of any file the process account can access - the custom function is a file-read sink in its own right, independent of whatever the `Eval` call is permitted to do on its own.

The fix keeps `Eval` and the interpreter setup exactly as they were and instead confines `LookupRate`: it now maps `configKey` through a fixed, server-defined dictionary of legitimate rate keys to their real file paths, and only ever calls `File.ReadAllText` with the resolved, trusted path from that dictionary. An expression can still ask for `lookupRate("standard")`, but it can no longer supply a path of its own - any key outside the allowlist is rejected with `ArgumentException` before the file system is touched. This is the canonical-value substitution the allowlist requires: the trusted path from the dictionary is what reaches the sink, never the caller-supplied string.

## Behaviour changes

- **`LookupRate` now rejects any `configKey` not in `RateConfigFiles`**, throwing `ArgumentException` instead of attempting a file read. Reason: this is the control that closes the arbitrary-file-read path; previously any string, including one denoting a file outside the intended configuration directory, was accepted.
- **The file path passed to `File.ReadAllText` is now the dictionary's value, not the caller-supplied `configKey`.** Reason: required by the allowlist fix - the expression may only select a known key, never dictate a path.
- **Placeholder paths (`standard`/`seasonal`/`clearance` -> `C:\config\rates\*.txt`) are illustrative.** The real key set and file locations must be filled in from the application's actual rate-configuration data; no other behaviour of `Evaluate` or the interpreter setup changed.
- Everything else - `Evaluate`'s signature and body, `SetVariable`/`SetFunction` registration, `decimal.Parse` on the file's contents, and the exception behaviour of `File.ReadAllText`/`decimal.Parse` for a resolved path - is unchanged.

## Verification

Compiled the fixed file with a real DynamicExpresso dependency: created a scratch .NET 10 class library, added the `DynamicExpresso.Core` NuGet package (resolved version 2.19.5), copied the fixed `DiscountRuleEvaluator.cs` into it unmodified from what appears above, and ran `dotnet build`. Result: `Build succeeded. 0 Warning(s). 0 Error(s).` This confirms `Dictionary<string,string>`, `IReadOnlyDictionary<string,string>`, `ArgumentException`, and the `TryGetValue` call all resolve correctly against the .NET base class library, and that the file is syntactically and semantically valid alongside the unmodified `DynamicExpresso.Interpreter` usage.

## Assumptions

- `rule` has no validation between an external caller and `Evaluate` (no such caller exists in the single-file case directory), so it is treated as the untrusted source per the CWE-94 guidance's default posture of treating all input as untrusted regardless of origin.
- The concrete allowlist keys and file paths are illustrative placeholders standing in for the application's real rate-configuration key set, which is not present in the provided file.
