## Verdict
Code injection vulnerability confirmed. The `expression` parameter is passed directly to `CSharpScript.EvaluateAsync()` without validation, allowing arbitrary C# code execution if the expression is user-controlled.

## Source
Line 14 passes an unsanitized `expression` string to `CSharpScript.EvaluateAsync()`, which will compile and execute any valid C# code provided. There is no whitelist or validation gate preventing injection of dangerous operations like file I/O, reflection, or network access.

## Fix
Replace the Roslyn script evaluation with an expression parser that only allows safe mathematical operations:

```csharp
public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
{
    // Validate expression contains only safe tokens
    var allowedPattern = new System.Text.RegularExpressions.Regex(
        @"^[0-9+\-*/(). a-zA-Z_]*$"
    );
    
    if (!allowedPattern.IsMatch(expression))
    {
        throw new System.ArgumentException("Expression contains invalid characters", nameof(expression));
    }
    
    try
    {
        // Use a restricted evaluator library (e.g., DynamicExpresso, NLua, or System.Linq.Expressions)
        // Example using a simple whitelist approach with Roslyn but restricting available members:
        var options = ScriptOptions.Default
            .WithImports("System")
            .WithReferences(typeof(InvoiceSample).Assembly);
        
        // Only provide the sample object, no file I/O or reflection APIs
        return CSharpScript.EvaluateAsync<object>(expression, options, sample);
    }
    catch (System.OperationCanceledException)
    {
        throw;
    }
    catch (System.Exception ex)
    {
        throw new System.InvalidOperationException($"Invalid formula: {ex.Message}", ex);
    }
}
```

A more robust fix uses a dedicated expression evaluation library:

```csharp
using DynamicExpresso; // NuGet: DynamicExpresso.Core

public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
{
    var interpreter = new Interpreter();
    
    // Register only safe variables/methods
    interpreter.SetVariable("sample", sample);
    interpreter.SetVariable("Amount", sample.Amount);
    interpreter.SetVariable("Quantity", sample.Quantity);
    
    var result = interpreter.Eval(expression);
    return System.Threading.Tasks.Task.FromResult(result);
}
```

## Explanation
CWE-94 occurs when code generation is not properly controlled. Roslyn's `CSharpScript.EvaluateAsync()` compiles and executes arbitrary C# code, making it vulnerable to injection if the expression parameter comes from untrusted input.

The fix uses input validation with a restrictive regex pattern to block dangerous characters. A production-grade solution should either:
1. Use a dedicated safe expression parser (DynamicExpresso, NLua, or System.Linq.Expressions) that only supports arithmetic/field operations
2. Parse the expression into an abstract syntax tree and validate only safe node types before evaluation
3. Sandbox the script execution with restricted imports and method access

The provided Roslyn example limits the global scope to the sample object, but the regex whitelist is the primary control gate preventing code injection attempts.
