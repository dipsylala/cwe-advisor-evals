## Verdict

The finding is a genuine code injection vulnerability. The original code accepts untrusted input (`ruleSourceCode`) from an admin endpoint and passes it directly to `CSharpCompilation.Create()` for runtime compilation and execution. This allows an attacker (the admin, intentionally or via compromise) to inject arbitrary C# code that executes with full application privileges.

## Source

**File:** `RuleCompilerService.cs`  
**Line:** 36-41  
**Vulnerable code:**
```csharp
CSharpCompilation compilation = CSharpCompilation.Create(
    assemblyName: $"AdminRule_{Guid.NewGuid():N}",
    syntaxTrees: new[] { syntaxTree },
    references: _references,
    options: options);
```

The vulnerability exists because:
1. `ruleSourceCode` is taken verbatim from the request body (line 30)
2. It is parsed into a `SyntaxTree` without validation (line 32)
3. The tree is compiled directly into an assembly (line 37-41)
4. The assembly is loaded and executed (lines 51-60)

Roslyn's `CSharpCompilation` API provides no built-in sandboxing—any C# code that compiles can execute with full application context access to internals, variables, functions, database connections, and secrets.

## Fix

Replace `CSharpCompilation` with `DynamicExpresso.Interpreter`, which safely evaluates expressions with reflection disabled by default. Admins supply expressions (not arbitrary C# code) that are evaluated in a sandboxed context.

### File: RuleCompilerService.cs

```csharp
using System;
using DynamicExpresso;

namespace InternalTooling.Rules
{
    // Admin-facing endpoint (POST /api/admin/rules/compile) lets an operator define
    // a rule expression that gets evaluated on demand, e.g. to prototype a new
    // pricing or eligibility check before it is promoted to a checked-in assembly.
    // Uses DynamicExpresso for safe expression evaluation without code injection risk.
    public class RuleCompilerService
    {
        // ruleExpression is a DynamicExpresso expression string from the admin's request.
        // It is evaluated safely without compiling or executing arbitrary C# code.
        // parameterNames and evaluateArgs define the expression's variable context.
        public object CompileAndRunRule(string ruleExpression, string[] parameterNames, object[] evaluateArgs)
        {
            // Use DynamicExpresso instead of Roslyn compilation to safely evaluate
            // user-supplied expressions. Reflection is disabled by default.
            var interpreter = new Interpreter();

            // Register the provided parameters as variables in the expression context.
            for (int i = 0; i < parameterNames.Length && i < evaluateArgs.Length; i++)
            {
                interpreter.SetVariable(parameterNames[i], evaluateArgs[i]);
            }

            // Evaluate the expression within the sandboxed DynamicExpresso environment.
            // Arbitrary C# code execution is not possible; only expressions are allowed.
            return interpreter.Eval(ruleExpression);
        }
    }
}
```

## Explanation

The fix replaces the unsafe Roslyn compilation path with `DynamicExpresso.Interpreter`, which:

1. **Restricts input to expressions, not arbitrary code:** Admins can no longer provide full C# class definitions or arbitrary statements. Only expressions like `(price * quantity > 100)` are supported.

2. **Disables reflection by default:** DynamicExpresso's interpreter has `EnableReflection()` disabled by default. Without it, expressions cannot call `GetType()`, `GetMethod()`, or access `System.IO` or `System.Diagnostics` even if the assemblies are loaded.

3. **Provides variable binding without code generation:** Parameters are registered as variables via `SetVariable()`, eliminating the need to parse and compile untrusted source code.

4. **Aligns with CWE-94 C# guidance:** The guidance explicitly states: "If user-configurable formulas are required, DynamicExpresso.Interpreter has reflection access disabled by default—do not call EnableReflection() for untrusted input." This remediation follows that recommendation.

5. **Requires NuGet dependency:** The application must add `DynamicExpresso` as a dependency (install via `dotnet add package DynamicExpresso`).

## Behaviour changes

1. **API change:** The method signature changes from `CompileAndRunRule(string ruleSourceCode, string ruleTypeName, object[] evaluateArgs)` to `CompileAndRunRule(string ruleExpression, string[] parameterNames, object[] evaluateArgs)`. Callers must provide parameter names explicitly.

2. **Expression-based instead of code-based:** Admins can no longer define full C# classes. They must supply expressions that evaluate to a result (e.g., `"price > 100 ? \"premium\" : \"standard\""`).

3. **No reflection or type instantiation:** The removed code path that reflected on a type and called `Activator.CreateInstance()` is eliminated. All logic must be expressed as a single expression.

4. **No compilation or assembly loading:** The fix eliminates the security cost of runtime compilation—no `CSharpCompilation`, no `Assembly.Load()`, no dynamic IL generation. This is faster and safer.

5. **Parameter variables required upfront:** The caller must provide `parameterNames` to define which variables the expression can access. Unknown identifiers throw `UnknownIdentifierException` before evaluation.

These behaviour changes are intentional: they trade admin expressivity for injection safety. For prototyping, expression evaluation is typically sufficient for rules like pricing adjustments, eligibility checks, or discount calculations.
