## Verdict

Confirmed exploitable. User-supplied expression passed directly to `CSharpScript.EvaluateAsync()` at line 14 allows arbitrary C# code execution with full access to the application's runtime, libraries, and system APIs.

## Source

HTTP request body (`FormulaPreviewController.cs`, line 19) → `request.Expression` parameter → `_evaluator.EvaluateAsync(request.Expression, ...)` → `CSharpScript.EvaluateAsync(expression, ...)` (line 14).

No validation or allowlist between source and sink. The Roslyn scripting API compiles and executes the string as C# code within the application's process context, granting attackers access to `System.IO`, reflection, and any referenced assembly.

## Fix

Replace Roslyn's unrestricted dynamic compilation with `DynamicExpresso.Interpreter`, which has reflection disabled by default and restricts evaluation to registered variables and functions:

**FormulaEvaluator.cs (fixed):**

```csharp
using DynamicExpresso;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    public object? Evaluate(string expression, InvoiceSample sample)
    {
        var interpreter = new Interpreter();
        interpreter.SetVariable("Total", sample.Total);
        interpreter.SetVariable("Tax", sample.Tax);
        
        return interpreter.Eval(expression);
    }
}
```

**FormulaPreviewController.cs (fixed):**

```csharp
[HttpPost("preview")]
public IActionResult Preview([FromBody] FormulaPreviewRequest request)
{
    var value = _evaluator.Evaluate(request.Expression, new InvoiceSample(100, 8));
    return Ok(new { value });
}
```

Add `DynamicExpresso` NuGet package to the project (no version floor specified in guidance; confirm against SCA tooling that the resolved version carries no open advisories before merging).

## Explanation

`DynamicExpresso.Interpreter` is a lightweight expression evaluator designed for user-supplied formulas. Unlike Roslyn, it does not support reflection, type instantiation, or arbitrary method invocation by default. Only variables explicitly registered via `SetVariable()` are available in the expression scope—in this case, `Total` and `Tax` from the invoice. Attempting to reference `System.IO.File` or invoke reflection returns `UnknownIdentifierException` instead of executing code.

The swap from `EvaluateAsync` to synchronous `Eval` is safe here because formula evaluation is typically fast; if async is required downstream, `Task.FromResult()` can wrap the result at the controller level.

## Behaviour changes

- Expressions are now limited to arithmetic, boolean logic, and the two registered variables (`Total`, `Tax`). Complex C# syntax (method calls, type references, LINQ) is rejected with `UnknownIdentifierException` at evaluation time.
- Reflection and file I/O attempts fail early instead of executing.
- No assembly loading or external code compilation occurs.
- Performance is faster (simple interpretation vs. compilation).
- Async call is replaced with sync; if async is needed, wrap the result in `Task.FromResult()`.

