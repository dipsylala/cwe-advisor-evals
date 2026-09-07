## Verdict

CONFIRMED. The vulnerability is exploitable. The method accepts untrusted C# source code from an admin POST request, compiles it dynamically via `CSharpCompilation.Create()`, loads the compiled assembly, and executes it via reflection without any restrictions or sandboxing. Per CWE-94/csharp guidance: "No Roslyn API sandboxes execution by default — the only reliable isolation is a separate process with limited permissions." This endpoint should not support dynamic compilation.

## Source

Parameter `string ruleSourceCode` (line 29), supplied from the HTTP POST request body, flows directly to `CSharpSyntaxTree.ParseText(ruleSourceCode)` (line 31), then to `CSharpCompilation.Create()` (line 36). The untrusted input is compiled to IL and executed via reflection (lines 50, 52-59).

## Fix

Replace dynamic compilation with a predefined rule registry. Remove the `ruleSourceCode` parameter and lookup rule implementations by a registered name:

```csharp
using System;
using System.Collections.Generic;
using System.Reflection;

namespace InternalTooling.Rules
{
    // Admin-facing endpoint (POST /api/admin/rules/evaluate) invokes a predefined rule
    // implementation from a registry. New rules must be compiled and checked into the codebase,
    // not submitted as source text.
    public class RuleCompilerService
    {
        // Predefined rule types, registered at development time.
        private static readonly Dictionary<string, Type> PredefinedRules = new()
        {
            // Add rule implementations as they are created:
            // { "PricingRule_v1", typeof(PricingRule_v1) },
            // { "EligibilityCheck_v1", typeof(EligibilityCheck_v1) },
        };

        // Locates a rule type by its registered name and invokes its Evaluate method.
        // ruleName must be in the PredefinedRules dictionary; new rules require code changes.
        public object CompileAndRunRule(string ruleName, object[] evaluateArgs)
        {
            if (!PredefinedRules.TryGetValue(ruleName, out var ruleType))
            {
                throw new InvalidOperationException(
                    $"Rule '{ruleName}' is not registered. Supported rules: {string.Join(", ", PredefinedRules.Keys)}");
            }

            object ruleInstance = Activator.CreateInstance(ruleType)
                ?? throw new InvalidOperationException($"Could not instantiate '{ruleName}'.");
            MethodInfo evaluateMethod = ruleType.GetMethod("Evaluate")
                ?? throw new InvalidOperationException($"Rule type '{ruleName}' has no 'Evaluate' method.");

            return evaluateMethod.Invoke(ruleInstance, evaluateArgs);
        }
    }
}
```

## Explanation

The fix eliminates dynamic code compilation by removing the `ruleSourceCode` parameter entirely and replacing it with a predefined rule registry (`PredefinedRules`). Rule implementations are now compiled and checked into the codebase at development time, not provided as untrusted text at runtime. When an admin requests a rule evaluation, the method looks up the rule by name in the dictionary, validates it exists, instantiates it, and invokes its `Evaluate` method. This removes the attack surface entirely: there is no parsing, compilation, or reflection on untrusted code. The `Assembly.Load()` call is eliminated, and type instantiation is confined to only the types registered in the dictionary. This aligns with CWE-94/csharp guidance: "Replace dynamic compilation with predefined delegates, strategy patterns, or configuration-driven dispatch."

## Behaviour changes

- Method signature changes: `ruleSourceCode` parameter is removed. Callers must now pass a rule name that is registered in `PredefinedRules`, not arbitrary C# source.
- Endpoint semantics: POST `/api/admin/rules/evaluate` now accepts `{ ruleName: string, evaluateArgs: object[] }` instead of `{ ruleSourceCode: string, ruleTypeName: string, evaluateArgs: object[] }`.
- New rules require code changes: admins can no longer prototype rules by pasting source text. Rule implementations must be compiled and merged into the codebase.
- Error messages: if a rule name is not found, the response now lists registered rule names to aid discovery.
- Performance: eliminates compilation overhead; rule instantiation and reflection remain, but operate only on predefined types.
- Backwards compatibility: breaking change for any client that relied on the old endpoint's dynamic compilation capability. Migration: pre-compile candidate rules as classes, register them in `PredefinedRules`, and update clients to use rule names instead of source text.
