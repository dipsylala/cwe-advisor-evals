## Verdict

CWE-94 (Improper Control of Generation of Code) — **exploitable**, confidence high.

Location: `FormulaEvaluator.cs:14`, `CSharpScript.EvaluateAsync(expression, options, sample)`.

## Source

- **Source**: HTTP request body field `Expression` on `POST api/formulas/preview` (`FormulaPreviewController.Preview`, bound via `[FromBody] FormulaPreviewRequest request`) — fully attacker-controlled, no validation anywhere in the chain.
- **Flow**: `FormulaPreviewController.Preview` passes `request.Expression` unmodified into `_evaluator.EvaluateAsync(request.Expression, new InvoiceSample(100, 8))`.
- **Sink**: `FormulaEvaluator.EvaluateAsync` (`FormulaEvaluator.cs:14`) hands that string straight to `CSharpScript.EvaluateAsync(expression, options, sample)`, with `ScriptOptions` importing `System` and `System.IO` and referencing the `InvoiceSample` assembly. Roslyn compiles and executes the string as live C#, with file I/O already in scope via the `System.IO` import — arbitrary code execution in the process, not just formula evaluation.
- **Sink contract**: returns whatever the script evaluates to as `object?`, discards the `ScriptState`, leaves globals/cancellation/assembly-load-context at their defaults, and throws `Microsoft.CodeAnalysis.Scripting.CompilationErrorException` on invalid script text (unhandled by the controller, surfaces as an unhandled exception).

## Fix

### File: FormulaEvaluator.cs

```csharp
using DynamicExpresso;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        var interpreter = new Interpreter()
            .SetVariable("Total", sample.Total)
            .SetVariable("Tax", sample.Tax);

        var result = interpreter.Eval(expression);
        return System.Threading.Tasks.Task.FromResult<object?>(result);
    }
}
```

Requires adding the NuGet package `DynamicExpresso.Core` to the project file. That project file is not one of the two files forming this case's call chain, so it is not reproduced here; add `<PackageReference Include="DynamicExpresso.Core" Version="..." />` and resolve the version through the project's SCA/dependency-check tooling rather than pinning one from this write-up — the loaded CWE-94/C# guidance names the library but gives no minimum safe version.

## Explanation

The vulnerability is that `CSharpScript.EvaluateAsync` compiles and runs the request body's `Expression` as arbitrary C#, with `System`/`System.IO` already imported — a "formula" endpoint is really an unauthenticated remote-code-execution endpoint. The loaded guidance's C#-specific branch for this exact scenario ("if a formula evaluator is required") is to swap Roslyn scripting for `DynamicExpresso.Interpreter`, which parses only its own expression grammar (arithmetic/comparison over explicitly registered identifiers) and has no member-access syntax onto arbitrary types unless reflection is turned on. The fix registers just the two fields the formula needs, `Total` and `Tax`, as interpreter variables via `SetVariable`, references no namespaces or types, and does not call `EnableReflection()` — leaving reflection at the library's default-disabled state. This removes the compiler/script sink entirely rather than trying to filter the input string.

Verification: copied the fixed class into a scratch .NET 10 console project, added `DynamicExpresso.Core` (resolved live from nuget.org, version 2.19.5), and ran it against `InvoiceSample(100, 8)`. A legitimate formula `"Total + (Total * Tax / 100)"` evaluated to `108` as expected. The equivalent of the original sink's payload, `"System.IO.File.Delete(\"C:/pwned.txt\")"`, was rejected with `UnknownIdentifierException` ('System' is not a registered identifier — no namespace is referenced). A reflection-based probe, `"Total.GetType().Assembly.GetType(...)"`, was rejected with `ReflectionNotAllowedException`. All three checks passed, confirming both that the legitimate use case still works and that the injection path is closed.

## Behaviour changes

- **Expression surface narrows**: from arbitrary C# (any statement, any type reachable via the imported namespaces and referenced assembly) to DynamicExpresso's expression grammar over two explicitly registered identifiers, `Total` and `Tax`. This is the change that closes the weakness; a formula referencing anything else now fails to parse instead of executing.
- **Exception type on bad input changes**: from Roslyn's `CompilationErrorException` to DynamicExpresso's `ParseException` / `UnknownIdentifierException` / `ReflectionNotAllowedException`. `FormulaPreviewController.Preview` does not catch either today, so in both the original and fixed code an invalid expression surfaces as an unhandled exception to the caller — no change in externally observable failure behaviour.
- **Evaluation is synchronous under the hood**: `Interpreter.Eval` has no async form, so the method wraps its result in `Task.FromResult` rather than truly awaiting. The public signature (`Task<object?> EvaluateAsync(string, InvoiceSample)`) and the `await`-based caller in `FormulaPreviewController` are unchanged.
- **Dropped `ScriptOptions` imports/reference**: `System`, `System.IO`, and the reference to the `InvoiceSample` assembly are no longer supplied to an evaluator, since nothing legitimate depended on script-level access to them — only the injection path used that surface.
