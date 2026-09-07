## Verdict

**Confirmed vulnerability:** CWE-94 code injection via `CSharpScript.EvaluateAsync()`.

The HTTP request body (`FormulaPreviewRequest.Expression`) flows directly into an untrusted parameter at line 14 of `FormulaEvaluator.cs`, where it is executed as arbitrary C# code via `CSharpScript.EvaluateAsync()`. An attacker can supply expressions containing `System.IO.File`, `System.Diagnostics.Process`, or reflection APIs to exfiltrate secrets, delete files, or compromise the application.

## Source

**Attacker-controlled input:** `FormulaPreviewController.Preview()` receives `request.Expression` from the HTTP POST body (`[FromBody] FormulaPreviewRequest`), unmarshalled as a string.

**Data flow:** `request.Expression` (line 19 in `FormulaPreviewController.cs`) → `_evaluator.EvaluateAsync(request.Expression, ...)` → `CSharpScript.EvaluateAsync(expression, options, sample)` (line 14 in `FormulaEvaluator.cs`, the sink).

## Fix

### File: FormulaEvaluator.cs

```csharp
using DynamicExpresso;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        // Use DynamicExpresso.Interpreter for safe expression evaluation with reflection disabled
        var interpreter = new Interpreter();
        
        // Explicitly register only the variables needed for the formula
        interpreter.SetVariable("Total", sample.Total);
        interpreter.SetVariable("Tax", sample.Tax);
        
        try
        {
            // Evaluate the expression in the restricted environment (no file/process/reflection access)
            var result = interpreter.Eval(expression);
            return System.Threading.Tasks.Task.FromResult(result);
        }
        catch (Exception ex)
        {
            // Wrap evaluation errors to prevent information leakage
            throw new InvalidOperationException("Expression evaluation failed: invalid expression or unauthorized operation", ex);
        }
    }
}
```

## Explanation

The fix replaces `CSharpScript.EvaluateAsync()` with `DynamicExpresso.Interpreter.Eval()`. 

**Why this closes the vulnerability:**
- `DynamicExpresso` is a sandboxed expression evaluator designed for safe, user-supplied formulas.
- Reflection is disabled by default in a new `Interpreter()` instance; calling `EnableReflection()` is not used.
- Only explicitly registered variables (`Total`, `Tax`) are accessible within expressions; attempting to access `System.IO.File`, `System.Diagnostics.Process`, or reflection APIs fails with `UnknownIdentifierException` before any code runs.
- The expression grammar supports arithmetic, comparison, and logical operators but not member access, method invocation, or namespace resolution that would reach dangerous APIs.

**Consequence:** Expressions like `Total + Tax`, `Total * 0.1`, or `Total > 100` evaluate safely. Malicious attempts like `System.IO.File.Delete("/etc/passwd")` or `typeof(System.IO.File).GetMethods()` are rejected with an exception, preventing code injection.

## Behaviour changes

- **Restricted operator set:** Expressions are limited to arithmetic, comparison, logical operators, and string concatenation. Complex formulas using custom methods, LINQ, or reflection fail.
- **Safer failure mode:** Invalid or malicious expressions raise `InvalidOperationException` instead of silently executing arbitrary code.
- **No ambient scope:** Expressions cannot reference any member of the `sample` object itself—only the scalar variables explicitly registered. Access to `sample.Total` or `sample.Tax` properties requires the application to register them as separate variables, which it now does.
- **Performance:** `DynamicExpresso.Eval()` is synchronous; the method wraps the result in `Task.FromResult()` to maintain the async signature and caller compatibility (the controller's `await` is unaffected).
