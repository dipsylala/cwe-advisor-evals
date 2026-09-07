## Verdict

exploitable

## Source

`FormulaPreviewController.Preview()` receives `request.Expression` from an HTTP POST request body ([FromBody] attribute), which is untrusted user input supplied by the HTTP client.

## Fix

**Vulnerable code:**
```csharp
public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
{
    var options = ScriptOptions.Default
        .WithImports("System", "System.IO")
        .WithReferences(typeof(InvoiceSample).Assembly);

    return CSharpScript.EvaluateAsync(expression, options, sample);  // Line 14: untrusted expression executed as C#
}
```

**Fixed code:**
```csharp
public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
{
    // Use DynamicExpresso instead of CSharpScript for safer formula evaluation
    var interpreter = new DynamicExpresso.Interpreter();
    
    // Register only the necessary variables - DynamicExpresso has reflection disabled by default
    interpreter.SetVariable("Total", sample.Total);
    interpreter.SetVariable("Tax", sample.Tax);
    
    // Evaluate the expression with restricted scope and no reflection
    var result = interpreter.Eval(expression);
    
    // Return as a completed task to preserve the async signature
    return System.Threading.Tasks.Task.FromResult((object?)result);
}
```

Add `using DynamicExpresso;` at the top of the file.

## Explanation

The original code uses Roslyn's `CSharpScript.EvaluateAsync()` to execute untrusted user input as arbitrary C# code. Per Roslyn's maintainers, there is no default isolation in Roslyn APIs—the only reliable containment is a separate process. The fix replaces this with `DynamicExpresso.Interpreter`, which is purpose-built for safely evaluating expressions. DynamicExpresso has reflection disabled by default and only grants access to explicitly registered variables (`Total` and `Tax` in this case), preventing access to `System.IO.File`, reflection APIs, or any other dangerous namespaces. This eliminates the attack surface while preserving the ability to evaluate formulas over the invoice data.

## Behaviour changes

- Returns a synchronously completed Task instead of an actual async operation (the evaluation is now blocking and immediate rather than potentially concurrent)
- No longer supports arbitrary C# syntax; limited to DynamicExpresso's expression grammar (no imports, namespaces, or statement-level code)
- Reflection is structurally disabled, preventing access to type metadata and method invocation on types
- Only `Total` and `Tax` variables are accessible (no access to `System.IO`, `System.Net`, or any namespaces)
- Callers cannot inject new namespaces via `WithImports()` or reference new assemblies via `WithReferences()`

All behaviour changes are intentional security restrictions that prevent code injection while preserving the legitimate formula-evaluation use case.
