## Verdict

Confirmed. CWE-94 (Code Injection) at line 36. The `CSharpCompilation.Create()` call accepts untrusted source code (`ruleSourceCode`) taken verbatim from an HTTP request body without validation, allowing an admin with access to the compile endpoint to inject and execute arbitrary C# code within the application's runtime context.

## Source

`ruleSourceCode` parameter (line 29) is documented as "the raw text of the admin's submitted .cs rule file, taken verbatim from the request body." This untrusted string is:
- Parsed into a syntax tree (line 31)
- Compiled via `CSharpCompilation.Create()` (line 36)
- Loaded into memory and executed via reflection (lines 50, 59)

An attacker with admin access to the POST endpoint can inject malicious C# code that executes with full access to the application's internals, connections, and secrets.

## Fix

Replace dynamic code compilation with a **strategy pattern** using predefined rule implementations. Instead of accepting arbitrary C# source, the endpoint accepts a rule name and arguments, which maps to a registered implementation:

```csharp
using System;
using System.Collections.Generic;

namespace InternalTooling.Rules
{
    // Define a common interface for all rules
    public interface IRule
    {
        object Evaluate(params object[] args);
    }

    // Example rule implementation (checked-in code, subject to review)
    public class PricingRule : IRule
    {
        public object Evaluate(params object[] args)
        {
            // Pricing logic here
            return true;
        }
    }

    public class EligibilityRule : IRule
    {
        public object Evaluate(params object[] args)
        {
            // Eligibility logic here
            return true;
        }
    }

    public class RuleFactory
    {
        private static readonly Dictionary<string, Func<IRule>> RuleRegistry =
            new()
            {
                { "pricing", () => new PricingRule() },
                { "eligibility", () => new EligibilityRule() },
                // Add new rules here as they are created
            };

        public static IRule CreateRule(string ruleName)
        {
            if (!RuleRegistry.TryGetValue(ruleName.ToLowerInvariant(), out var factory))
            {
                throw new InvalidOperationException($"Unknown rule: '{ruleName}'");
            }
            return factory();
        }
    }

    public class RuleCompilerService
    {
        // Removed dynamic compilation; now dispatch to static implementations
        public object CompileAndRunRule(string ruleName, object[] evaluateArgs)
        {
            // Allowlist: only permit registered rule names
            var rule = RuleFactory.CreateRule(ruleName);
            return rule.Evaluate(evaluateArgs);
        }
    }
}
```

## Explanation

The fix eliminates dynamic code compilation by:

1. **Removing the sink**: `CSharpCompilation.Create()` is no longer called with untrusted input.
2. **Using an allowlist**: Only predefined rule names that map to registered implementations are accepted. Any attempt to use an unregistered rule name fails with `InvalidOperationException`.
3. **Static dispatch**: Rule logic is defined in checked-in C# classes subject to code review, not submitted at runtime.
4. **Preserving the capability**: Admins can still prototype new rules by adding a new class to the codebase and registering it in `RuleFactory`, but this now requires a code review and deployment cycle instead of arbitrary code execution.

The Metadata Reference restrictions (`_references`) are removed because they are no longer needed—no compilation happens at runtime.

## Behaviour changes

- **API contract change**: The endpoint now accepts a rule name (string) instead of C# source code (string). Callers must be updated to pass a registered rule name.
- **No more arbitrary code execution**: Attempts to submit C# code are rejected; only predefined rules can be invoked.
- **Deployment workflow change**: New rules must be added to the codebase, reviewed, and deployed. There is no runtime compilation or dynamic rule addition.
- **Error handling**: Unrecognized rule names throw `InvalidOperationException` instead of compilation errors.
- **Testing**: The `Evaluate` method signature is now fixed by the interface contract. Tests can be added per rule implementation to verify logic; injection of arbitrary code via `Evaluate` arguments is not possible because the rule implementation is static.
