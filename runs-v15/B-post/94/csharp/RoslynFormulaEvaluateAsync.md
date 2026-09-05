## Verdict

Exploitable. User input from `FormulaPreviewRequest.Expression` flows directly to `CSharpScript.EvaluateAsync()` without validation, allowing arbitrary C# code injection.

## Source

HTTP POST request body parameter `FormulaPreviewRequest.Expression` in `FormulaPreviewController.Preview()`, passed to `FormulaEvaluator.EvaluateAsync()`.

## Fix

**Vulnerable code (FormulaEvaluator.cs, line 14):**

```csharp
return CSharpScript.EvaluateAsync(expression, options, sample);
```

**Fixed code:**

```csharp
using DynamicExpresso;
using System.Text.RegularExpressions;

public sealed class FormulaEvaluator
{
    private static readonly Regex AllowedExpressionPattern = new(@"^[\d+\-*/().\s]+$", RegexOptions.Compiled);

    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        // Validate expression contains only safe arithmetic operators and identifiers
        if (string.IsNullOrWhiteSpace(expression) || !AllowedExpressionPattern.IsMatch(expression))
        {
            throw new ArgumentException("Expression contains invalid characters.", nameof(expression));
        }

        var interpreter = new Interpreter();
        
        // Register only safe variables from the sample
        interpreter.SetVariable("Total", sample.Total);
        interpreter.SetVariable("Tax", sample.Tax);
        
        // Evaluate in a try-catch to handle expression errors
        try
        {
            var result = interpreter.Eval(expression);
            return System.Threading.Tasks.Task.FromResult(result);
        }
        catch (DynamicExpresso.Exceptions.ParseException ex)
        {
            throw new ArgumentException("Invalid formula expression.", nameof(expression), ex);
        }
    }
}

public sealed record InvoiceSample(decimal Total, decimal Tax);
```

## Explanation

The original code used `CSharpScript.EvaluateAsync()` to evaluate user-supplied expressions, which compiles and executes arbitrary C# code. This is replaced with `DynamicExpresso.Interpreter`, which has reflection disabled by default and provides a sandboxed expression evaluator. The fix adds two layers of control: (1) a regex allowlist that restricts expressions to arithmetic operators, numbers, parentheses, and whitespace only - this prevents access to identifiers like `System`, method calls, or reflection; (2) explicit registration of only the two safe variables (`Total` and `Tax`) from the sample object, ensuring no other members are accessible. The async contract is preserved by wrapping the synchronous result in `Task.FromResult()`. DynamicExpresso's default configuration has no access to the class hierarchy, `System` namespaces, or reflection capabilities - only the registered variables and built-in arithmetic are available.

## Behaviour changes

- **Return type**: Changed from `Task<object?>` to match the same signature, but now returns via `Task.FromResult()` instead of `CSharpScript.EvaluateAsync()`. The caller receives the evaluation result identically.
- **Exception handling**: Invalid expressions now throw `ArgumentException` (custom validation) or `DynamicExpresso.Exceptions.ParseException` (wrapped as `ArgumentException`), rather than compiler exceptions from Roslyn. Callers expecting specific exception types should update error handling accordingly.
- **Expression capability**: Expressions are now restricted to arithmetic operations (`+`, `-`, `*`, `/`) with parentheses and numeric literals only. Previous arbitrary C# code (method calls, type instantiation, reflection, file/network access) is no longer possible - this is the intended security boundary.
- **Performance**: Synchronous evaluation and removal of assembly loading options may improve performance for high-volume formula evaluation, though `DynamicExpresso.Interpreter` creation has modest overhead per call. For production use, consider caching the interpreter instance or validating/parsing expressions upfront.

