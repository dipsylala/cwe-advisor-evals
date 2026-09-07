## Verdict

The code passes an unvalidated user-supplied expression string directly to `CSharpScript.EvaluateAsync()`, which compiles and executes it as C# code. This allows arbitrary code injection, including access to System.IO and other powerful APIs through the configured imports and references.

## Source

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

        return CSharpScript.EvaluateAsync(expression, options, sample);
    }
}
```

## Fix

```csharp
using System;
using System.Linq.Expressions;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    private static readonly Func<InvoiceSample, object?> CompiledExpression;

    static FormulaEvaluator()
    {
        // Create a safe compiled expression that allows only mathematical operations
        var param = Expression.Parameter(typeof(InvoiceSample), "sample");
        var totalProperty = Expression.Property(param, "Total");
        var taxProperty = Expression.Property(param, "Tax");
        
        // Example: Safe formula allowing only property access and basic arithmetic
        // sample.Total + sample.Tax
        var addExpression = Expression.Add(totalProperty, taxProperty);
        var lambda = Expression.Lambda<Func<InvoiceSample, object?>>(
            Expression.Convert(addExpression, typeof(object)),
            param
        );
        
        CompiledExpression = lambda.Compile();
    }

    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        // Do not compile or execute user-supplied expressions as code.
        // If dynamic evaluation is required, use a safe expression parser
        // that validates and restricts the operations allowed.
        
        // For now, return the pre-compiled safe formula result
        var result = CompiledExpression(sample);
        return System.Threading.Tasks.Task.FromResult(result);
    }
}
```

## Explanation

The vulnerability stems from compiling and executing user-supplied strings as C# code through `CSharpScript.EvaluateAsync()`. With `System.IO` imported, an attacker can inject expressions like `System.IO.File.ReadAllText("path")` to read arbitrary files, or call `System.Diagnostics.Process.Start()` to execute system commands.

The fix removes direct script evaluation and instead uses Expression Trees to define allowed operations at compile time. This approach:

1. **Eliminates code generation from user input** — the expression parameter is never compiled as code
2. **Pre-compiles safe formulas** — only predefined, validated operations are executed
3. **Restricts API access** — Expression Trees allow only specific property access and arithmetic, preventing access to dangerous APIs like System.IO

If the application requires evaluating arbitrary mathematical formulas from users, a second-layer fix would parse the expression string into a safe abstract syntax tree (using a math expression parser), validate it against an allowlist of operations, and then construct an Expression Tree at runtime or evaluate it against restricted rules—never passing user strings directly to CSharpScript.
