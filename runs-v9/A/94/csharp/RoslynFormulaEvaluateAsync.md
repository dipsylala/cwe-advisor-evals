## Verdict

Confirmed. `FormulaEvaluator.EvaluateAsync` passes an attacker-controlled string straight into `Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.EvaluateAsync`, which compiles and executes it as live C#. This is not a restricted formula grammar; `CSharpScript` accepts arbitrary C# statements/expressions, and the script host is configured with `System.IO` imported and a reference to the assembly containing `InvoiceSample`. A caller can submit an "expression" that shells out, reads/writes files, reflects into private members of the host process, or otherwise runs arbitrary code with the worker process's privileges - this is CWE-94, Improper Control of Generation of Code.

## Source

`FormulaPreviewController.Preview` (`FormulaPreviewController.cs:17-21`) deserializes the request body into `FormulaPreviewRequest`, whose `Expression` property is fully attacker-controlled, and passes it unchanged to `_evaluator.EvaluateAsync(request.Expression, ...)` at line 19. `FormulaEvaluator.EvaluateAsync` (`FormulaEvaluator.cs:8-15`) forwards that same string as the `code` argument to `CSharpScript.EvaluateAsync` at line 14 - the sink. There is no parsing, allow-listing, or sandboxing between the HTTP body and script compilation/execution.

## Fix

Stop compiling the request body as C#. Replace the Roslyn scripting call with a restricted arithmetic-expression evaluator that only understands a formula grammar (numbers, `+ - * /`, parentheses, and a fixed set of named variables) and cannot execute arbitrary statements, invoke methods, or import namespaces.

```csharp
// FormulaEvaluator.cs
using System.Collections.Generic;
using System.Threading.Tasks;
using NCalc;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    // Only these identifiers may appear in a formula. Anything else is rejected
    // before evaluation, so the expression can never reach into host state.
    private static readonly HashSet<string> AllowedParameters =
        new(StringComparer.OrdinalIgnoreCase) { "Total", "Tax" };

    public Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        var expr = new Expression(expression, EvaluateOptions.NoStringLiteral);

        foreach (var name in expr.GetParametersNames())
        {
            if (!AllowedParameters.Contains(name))
            {
                throw new ArgumentException($"Unknown formula variable '{name}'.", nameof(expression));
            }
        }

        expr.Parameters["Total"] = sample.Total;
        expr.Parameters["Tax"] = sample.Tax;

        var result = expr.Evaluate();
        return Task.FromResult<object?>(result);
    }
}
```

`NCalc` (the `NCalc` NuGet package) parses and evaluates a self-contained arithmetic/logical grammar - it has no facility for arbitrary statements, method invocation on host types, `using` directives, or reflection, so even a maximally hostile `expression` string cannot escape formula evaluation into code execution. The explicit `AllowedParameters` check closes off NCalc's own identifier lookup as a probing vector (an unrecognized name throws before `Evaluate()` runs) and keeps the surface limited to exactly `Total` and `Tax`.

`FormulaPreviewController.cs` needs no change: it already just forwards `request.Expression` and the fixed `InvoiceSample` to the evaluator, and the safe evaluator's signature is unchanged.

If a wider expression language is genuinely required later, extend `AllowedParameters` and, if needed, register additional named functions explicitly through NCalc's function-evaluation event - do not reach back for `CSharpScript` or any other general-purpose script host for input that originates from an HTTP request body.

## Explanation

`CSharpScript.EvaluateAsync` is a general-purpose C# compiler/interpreter host: the `code` argument is not sanitized or constrained to an expression subset by the API itself, and `ScriptOptions.WithImports("System", "System.IO")` additionally hands the script a preloaded `System.IO` namespace, so a submitted "formula" can call `File.ReadAllText`, `Directory.GetFiles`, `Environment.GetEnvironmentVariable`, or construct arbitrary objects via `WithReferences(typeof(InvoiceSample).Assembly)`. There is no sandboxing boundary in Roslyn scripting that makes this safe for untrusted input - AppDomain-based sandboxing is unavailable on modern .NET, and running the host process itself with restricted OS-level privileges only limits blast radius, it does not stop code execution. The only reliable fix for "let a user type a formula" is to never treat that input as a programming language in the first place: parse it against a deliberately narrow grammar (arithmetic plus a closed set of named variables) using a library built for that purpose, and reject anything the grammar does not recognize before any evaluation happens. That is what the `NCalc`-based replacement above does, and it preserves the endpoint's actual purpose - evaluating a tax/total formula - without the ability to execute host code.
