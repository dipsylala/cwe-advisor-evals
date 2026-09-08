## Verdict

Confirmed. `DiscountRuleEvaluator.Evaluate` passes the caller-supplied `rule` string directly into `DynamicExpresso.Interpreter.Eval`, with no validation of its shape. `Eval` compiles and runs whatever expression it is given, and the interpreter has a custom function, `lookupRate`, registered on it that performs unrestricted file I/O (`File.ReadAllText(configKey)`). Because the attacker controls the full expression text, they control the argument passed to `lookupRate`, so a rule such as `lookupRate("C:\\secrets.txt")` (or a relative traversal path) causes the application to read and return the contents of an arbitrary file on disk. This is CWE-94: the expression text is treated as code, and the code an attacker can submit is unconstrained.

## Source

`rule`, the `string` parameter of `DiscountRuleEvaluator.Evaluate(string rule, decimal orderTotal)` (line 7). It flows unmodified into `interpreter.Eval(rule)` at line 14, which is the sink. The interpreter's own registered function `lookupRate` (line 11, implemented at line 17-20) is the secondary sink that turns the code-injection primitive into arbitrary file disclosure, since `configKey` there is whatever string literal the attacker wrote inside the rule expression.

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
    // Discount rules may only reference these rate keys. Each maps to a fixed, trusted
    // configuration file; a rule can never supply its own path, so lookupRate can no
    // longer be used to read arbitrary files even if a rule tries to.
    private static readonly IReadOnlyDictionary<string, string> RateConfigFiles =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["standardRate"] = "config/rates/standard.txt",
            ["premiumRate"] = "config/rates/premium.txt",
            ["clearanceRate"] = "config/rates/clearance.txt",
        };

    // A discount rule is a small arithmetic expression over the number `orderTotal` and
    // the built-in `lookupRate("<key>")` call. Tokens are matched one at a time from the
    // current position (\G), so the rule is accepted only if it is made up entirely of
    // tokens from this closed set. There is no token for `.`, `[`, `;`, `=`, or any
    // identifier other than the two named here, so member access, other function calls,
    // casts, and any other DynamicExpresso syntax can never reach the interpreter.
    private static readonly Regex RuleToken = new(
        @"\G\s*(?:(?<num>\d+(?:\.\d+)?)|(?<id>orderTotal|lookupRate)|(?<str>""[A-Za-z][A-Za-z0-9_]*"")|(?<op>[-+*/])|(?<paren>[()]))\s*",
        RegexOptions.Compiled);

    public object? Evaluate(string rule, decimal orderTotal)
    {
        if (rule is null)
        {
            throw new ArgumentNullException(nameof(rule));
        }

        ValidateRule(rule);

        var interpreter = new Interpreter();
        interpreter.SetVariable("orderTotal", orderTotal);
        interpreter.SetFunction("lookupRate", (Func<string, decimal>)LookupRate);

        return interpreter.Eval(rule);
    }

    // Rejects the rule unless it is composed entirely of the allowed arithmetic/lookup
    // grammar, and unless every lookupRate key it references is a known rate key. This
    // runs before the rule ever reaches DynamicExpresso's interpreter, so the interpreter
    // is never given anything outside the vocabulary this method has already approved.
    private static void ValidateRule(string rule)
    {
        var position = 0;
        var precedingLookupRate = false;

        while (position < rule.Length)
        {
            var match = RuleToken.Match(rule, position);
            if (!match.Success || match.Index != position)
            {
                throw new ArgumentException(
                    "Rule contains a character or token that is not allowed.", nameof(rule));
            }

            if (match.Groups["id"].Success)
            {
                precedingLookupRate = match.Groups["id"].Value == "lookupRate";
            }
            else if (match.Groups["str"].Success)
            {
                if (!precedingLookupRate)
                {
                    throw new ArgumentException(
                        "A quoted key may only appear as the argument to lookupRate(...).", nameof(rule));
                }

                var key = match.Groups["str"].Value.Trim('"');
                if (!RateConfigFiles.ContainsKey(key))
                {
                    throw new ArgumentException($"Unknown rate key '{key}'.", nameof(rule));
                }

                precedingLookupRate = false;
            }

            position = match.Index + match.Length;
        }
    }

    private static decimal LookupRate(string configKey)
    {
        if (!RateConfigFiles.TryGetValue(configKey, out var path))
        {
            throw new ArgumentException($"Unknown rate key '{configKey}'.", nameof(configKey));
        }

        return decimal.Parse(System.IO.File.ReadAllText(path));
    }
}
```

## Explanation

The original code let an attacker author arbitrary DynamicExpresso syntax and hand it straight to `Eval`, then gave that syntax a callable function that reads a file from a path the syntax itself supplies - so "evaluate a rule" was really "run attacker-chosen code that can read any file the process can access."

The fix does not remove the rule-evaluation feature; it closes the gap between what the feature needs and what the sink accepts:

- `ValidateRule` tokenizes `rule` against a closed vocabulary - decimal numbers, the identifiers `orderTotal` and `lookupRate`, arithmetic operators, parentheses, and quoted keys - matched strictly left-to-right with no gaps (`\G` plus an index check). Any character sequence outside that vocabulary (a `.` for member access, a different identifier, an extra function name, escape sequences, etc.) fails to tokenize and the rule is rejected before `Eval` ever sees it. This is an allowlist on the *grammar*, which is appropriate here because the application already defines what a rule is allowed to look like (an arithmetic expression plus rate lookups) - it is not a generic bolt-on filter.
- Every quoted string is required to immediately follow the `lookupRate` identifier and must be one of the three known rate keys, checked against `RateConfigFiles`. A rule can no longer put an arbitrary path, or any string at all, in that position.
- `LookupRate` itself now takes a key and resolves it through the same fixed dictionary rather than treating its argument as a filesystem path. Even if a future change to the grammar or a bug in `ValidateRule` let an unexpected key through, `LookupRate` still rejects anything not in the map, so it can never be turned into a path-traversal or arbitrary-file-read primitive. This closes the concrete exploit path (arbitrary file disclosure via `lookupRate`) as defense in depth, independent of the grammar check.
- `Interpreter.Eval` is still used for the actual arithmetic, since DynamicExpresso's own parser correctly rejects anything grammatically invalid; the token allowlist only needs to keep *disallowed vocabulary* (member access, other calls, arbitrary literals) from ever reaching it, not re-implement full expression parsing.

A legitimate rule such as `orderTotal * lookupRate("standardRate")` or `(orderTotal - 10) * 0.9` still evaluates exactly as before. A rule that tries to reference anything else - a different function, a property access, a literal path, an unregistered variable - is rejected with an `ArgumentException` at the validation step, before any code executes.
