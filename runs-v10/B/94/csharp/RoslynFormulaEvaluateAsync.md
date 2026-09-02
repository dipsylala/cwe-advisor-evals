## Verdict

Exploitable

## Source

The `expression` parameter of the `EvaluateAsync` method (line 8) is untrusted user input passed with no validation.

## Fix

**Vulnerable code:**
```csharp
public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
{
    var options = ScriptOptions.Default
        .WithImports("System", "System.IO")
        .WithReferences(typeof(InvoiceSample).Assembly);

    return CSharpScript.EvaluateAsync(expression, options, sample);  // Line 14: injection sink
}
```

**Fixed code:**
```csharp
using DynamicExpresso;

public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
{
    var interpreter = new Interpreter()
        .SetVariable("sample", sample);
    
    var result = interpreter.Eval(expression);
    return System.Threading.Tasks.Task.FromResult(result);
}
```

## Explanation

The original code compiles and executes untrusted user input as C# code via `CSharpScript.EvaluateAsync()` with access to `System` and `System.IO` namespaces, allowing arbitrary method invocation (file deletion, process execution, reflection, network access). The fix replaces Roslyn with `DynamicExpresso.Interpreter`, which evaluates expressions in a restricted grammar that supports mathematical and member-access operations on explicitly registered variables only. Reflection is disabled by default in DynamicExpresso, and no system namespaces are imported, preventing access to dangerous APIs. The expression is now confined to safe formula evaluation over the `sample` object's public members.

## Behaviour changes

- Returns a synchronously-completed `Task<object?>` instead of potentially asynchronous evaluation from Roslyn (minor: most formula evaluation is CPU-bound and synchronous in practice)
- Expression language is now limited to DynamicExpresso's grammar (variables, member access, operators, registered functions) instead of full C# syntax (intentional restriction that closes the vulnerability)
- No access to `System`, `System.IO`, or any other namespaces; member access is confined to the `sample` object (intentional restriction for security)
- Requires adding `DynamicExpresso` NuGet package as a dependency (required change)
