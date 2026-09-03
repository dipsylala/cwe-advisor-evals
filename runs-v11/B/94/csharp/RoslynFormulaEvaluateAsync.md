## Verdict

Confirmed. The `expression` parameter originates from untrusted HTTP request input and flows directly to `CSharpScript.EvaluateAsync()`, which compiles and executes arbitrary C# code. The `WithImports("System", "System.IO")` configuration escalates this to arbitrary file deletion and process execution.

## Source

FormulaPreviewController.Preview receives user input via `request.Expression`, passes it to `FormulaEvaluator.EvaluateAsync()`, which passes it unvalidated to `CSharpScript.EvaluateAsync(expression, options, sample)` at line 14 of FormulaEvaluator.cs.

## Fix

Replace Roslyn's `CSharpScript.EvaluateAsync()` with `DynamicExpresso.Interpreter`, configured with reflection disabled (the default) and no System namespace references. Register only the specific variables the formula needs:

```csharp
using DynamicExpresso;

public sealed class FormulaEvaluator
{
    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        var interpreter = new Interpreter();
        
        // Register only the specific fields the formula may access
        interpreter.SetVariable("Total", sample.Total);
        interpreter.SetVariable("Tax", sample.Tax);
        
        try
        {
            var result = interpreter.Eval(expression);
            return System.Threading.Tasks.Task.FromResult<object?>(result);
        }
        catch (DynamicExpresso.Exceptions.UnknownIdentifierException)
        {
            throw new InvalidOperationException($"Invalid formula: unknown identifier");
        }
        catch (DynamicExpresso.Exceptions.ParseException ex)
        {
            throw new InvalidOperationException($"Invalid formula: {ex.Message}");
        }
    }
}
```

## Explanation

The fix eliminates code injection by replacing Roslyn's general-purpose C# compiler with DynamicExpresso, which is purpose-built for safe expression evaluation. Key changes:

1. **No C# compilation**: DynamicExpresso parses and evaluates expressions in a restricted grammar (arithmetic, logic, method calls on registered objects) rather than compiling C# source. An attacker cannot inject `System.IO.File.Delete()` because the expression language has no member-access syntax for arbitrary types.

2. **Reflection disabled by default**: DynamicExpresso's default configuration has reflection off; no `GetType()`, `Type.GetType()`, or dynamic method invocation is available.

3. **Explicit variable scope**: Only `Total` and `Tax` are registered and available to the formula. An attacker cannot access `System`, `System.IO`, or any other namespace.

4. **Separate evaluation per request**: A new `Interpreter` instance per request prevents state leakage across users.

The fix preserves the existing return type (`Task<object?>`) and maintains the same functional contract—expressions evaluate to a numeric result for the invoice sample. It breaks the direct injection path by ensuring the input is always treated as data (an expression string conforming to DynamicExpresso's grammar), never as source code to be compiled.

## Behaviour changes

- **Expressions must use DynamicExpresso's expression grammar**, not C# syntax. Simple formulas like `Total * 1.1` or `Total + Tax` work unchanged. C# code like `System.IO.File.Delete()` now raises `UnknownIdentifierException` instead of executing.
- **Exceptions are caught and wrapped** in `InvalidOperationException` with a descriptive message, rather than propagating raw Roslyn exceptions.
- **Evaluation is synchronous** (returns a completed `Task<object?>`), since DynamicExpresso.Eval() is not async. If async evaluation is required, wrap it: `Task.FromResult(interpreter.Eval(expression))`.
- **Performance**: DynamicExpresso parses on every call; for high-frequency evaluation, cache the parsed expression via `interpreter.Parse()` and `interpreter.Eval(parsedExpression)`.
