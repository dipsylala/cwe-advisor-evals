## Verdict

Exploitable - CWE-94 (Improper Control of Generation of Code), confidence: high.

`FormulaEvaluator.EvaluateAsync()` compiles and runs an attacker-controlled string with the Roslyn C# scripting engine. There is no allowlist, length cap, or sandboxing anywhere on the path, so an attacker who can reach `POST /api/formulas/preview` can execute arbitrary C# in the application's process - including `System.IO` file access, since that namespace is explicitly imported into the script's scope.

## Source

- **Source**: `FormulaPreviewRequest.Expression`, bound from the JSON request body in `FormulaPreviewController.Preview()` (`FormulaPreviewController.cs:17-19`).
- **Path**: `Preview()` calls `_evaluator.EvaluateAsync(request.Expression, new InvoiceSample(100, 8))` (`FormulaPreviewController.cs:19`) with no validation of `request.Expression` beforehand.
- **Sink**: `FormulaEvaluator.EvaluateAsync()` passes the value straight through to `CSharpScript.EvaluateAsync(expression, options, sample)` (`FormulaEvaluator.cs:14`), compiling and executing it with `ScriptOptions` that import `System` and `System.IO` and reference the assembly containing `InvoiceSample`.
- No sanitization, allowlist, or type/AST restriction exists anywhere between source and sink.

**Sink contract** (`CSharpScript.EvaluateAsync`):
- *Returns*: `Task<object?>` - the boxed result of the last script expression, awaited by the controller and serialized back to the caller as `{ value }`.
- *Discards*: nothing extra is captured today, but the script runs with full access to the CLR - any side effect (file write, process start, env read) happens regardless of what the return value is used for.
- *Implicit arguments*: no `CancellationToken` is passed (default `default`, so a runaway script cannot be cancelled by the caller); the `globals` parameter (`sample`) exposes `Total` and `Tax` as script-level identifiers, which is the mechanism legitimate formulas rely on.
- *Failure behaviour*: a malformed expression throws `Microsoft.CodeAnalysis.Scripting.CompilationErrorException`; a runtime fault throws whatever the script itself threw. Neither is currently caught, so both propagate to ASP.NET Core's default exception handling.

## Fix

**Library recommendation**: replace the Roslyn scripting engine with `DynamicExpresso` (NuGet package `DynamicExpresso.Core`), the sandboxed-formula pattern the CWE-94 C# guidance recommends for exactly this "user-configurable formula" scenario. The knowledge base does not carry a minimum safe version for this package - resolve and pin the version through your SCA/dependency-check tooling before merging, rather than trusting a version number here. `DynamicExpresso.Interpreter` has reflection disabled by default and, unless the code calls `EnableReflection()` or `Reference(typeof(T))`, its expression grammar exposes no member-access, file, process, or reflection surface - only the variables and functions the application registers explicitly.

Vulnerable code (`FormulaEvaluator.cs`):

```csharp
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        var options = ScriptOptions.Default
            .WithImports("System", "System.IO")
            .WithReferences(typeof(InvoiceSample).Assembly);

        // VULNERABLE: attacker-controlled `expression` is compiled and executed
        // as arbitrary C# with System/System.IO imported into scope.
        return CSharpScript.EvaluateAsync(expression, options, sample);
    }
}
```

Fixed code:

```csharp
using DynamicExpresso;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        // Default Interpreter: reflection disabled, no namespaces referenced,
        // only the two identifiers a formula legitimately needs are exposed.
        var interpreter = new Interpreter()
            .SetVariable("Total", sample.Total)
            .SetVariable("Tax", sample.Tax);

        var result = interpreter.Eval(expression);
        return System.Threading.Tasks.Task.FromResult<object?>(result);
    }
}
```

## Explanation

The fix removes the Roslyn scripting engine entirely, so the attacker-controlled string can no longer be compiled and run as general-purpose C# - there is no code-generation sink left for it to reach. In its place, `DynamicExpresso.Interpreter` evaluates the same string as a constrained arithmetic/logical expression: only the `Total` and `Tax` identifiers the application registers via `SetVariable` are resolvable, reflection stays off (the library's default), and no `System` namespace is referenced, so the expression grammar has no path to file, process, network, or reflection APIs. This preserves the feature's intent - the caller can still write formulas like `Total * Tax / 100` - while eliminating the ability to execute arbitrary code.

## Behaviour changes

- **Return type/signature unchanged** - `EvaluateAsync(string, InvoiceSample)` still returns `Task<object?>`, so `FormulaPreviewController.Preview()` requires no changes.
- **Result type may differ**: `CSharpScript.EvaluateAsync` returned whatever type the last script statement produced; `Interpreter.Eval()` returns the expression's value with a narrower, expression-oriented type system (numeric, boolean, string). For simple arithmetic formulas like `Total * Tax / 100` the observable result is equivalent; multi-statement scripts or expressions that relied on C# statement syntax are no longer possible - that capability is exactly the injection surface being removed, not a supported use case.
- **Failure behaviour changes**: an invalid expression now throws `DynamicExpresso.Exceptions.ParseException` or `DynamicExpresso.Exceptions.UnknownIdentifierException` instead of `CompilationErrorException`. Neither the original nor the fixed code catches these, so both currently propagate to ASP.NET Core's default exception handling - if the caller wants a friendlier 400 response for bad formulas, that requires an explicit `catch`, which is a separate concern from this fix.
- **`System`/`System.IO` imports and the `InvoiceSample` assembly reference are dropped**: the fixed code no longer gives the expression access to the `System` namespace at all, which is required to close the weakness. Legitimate formulas only ever needed the `Total`/`Tax` values, not the imported namespaces themselves.
- **No `CancellationToken` support was added**: the original omitted one too, so this preserves rather than changes the sink contract; if request-level cancellation is desired it should be added as a separate enhancement.
