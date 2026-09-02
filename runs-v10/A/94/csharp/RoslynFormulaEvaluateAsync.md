## Verdict

The code is vulnerable to CWE-94 (Improper Control of Generation of Code). The `CSharpScript.EvaluateAsync()` method compiles and executes arbitrary C# code based on the user-supplied `expression` parameter, allowing remote code execution with application privileges.

## Source

The vulnerability exists in `FormulaEvaluator.cs` at line 14:

```csharp
return CSharpScript.EvaluateAsync(expression, options, sample);
```

The `expression` parameter originates from the HTTP request body (`FormulaPreviewRequest.Expression` in the controller), making it attacker-controlled. An adversary can inject arbitrary C# code to:
- Access the file system (via imported `System.IO`)
- Invoke arbitrary methods on the `InvoiceSample` object
- Execute any operation the application process can perform

## Fix

```csharp
using System;
using System.Data;
using System.Text.RegularExpressions;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        // Validate expression before evaluation
        ValidateExpression(expression);

        try
        {
            // Use DataTable.Compute for safe mathematical expression evaluation
            // instead of dynamic code compilation with Roslyn
            var table = new DataTable();
            table.Columns.Add("Total", typeof(decimal));
            table.Columns.Add("Tax", typeof(decimal));
            
            var row = table.NewRow();
            row["Total"] = sample.Total;
            row["Tax"] = sample.Tax;
            table.Rows.Add(row);
            
            var result = table.Compute(expression, null);
            return System.Threading.Tasks.Task.FromResult(result);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Invalid formula expression.", nameof(expression), ex);
        }
        catch (EvaluateException ex)
        {
            throw new ArgumentException("Formula evaluation failed.", nameof(expression), ex);
        }
    }

    private static void ValidateExpression(string expression)
    {
        if (string.IsNullOrWhiteSpace(expression))
            throw new ArgumentException("Expression cannot be empty.", nameof(expression));

        // Restrict to alphanumerics, mathematical operators, parentheses, and decimal points only
        if (!Regex.IsMatch(expression, @"^[a-zA-Z0-9\+\-\*\/\(\)\.\s]+$"))
            throw new ArgumentException("Expression contains invalid characters.", nameof(expression));

        // Block common code injection patterns
        var blockedPatterns = new[] { "..", "__", "System", "File", "Process", "Reflection", "Assembly" };
        foreach (var pattern in blockedPatterns)
        {
            if (expression.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Expression contains blocked patterns.", nameof(expression));
        }
    }
}
```

## Explanation

The fix replaces dangerous dynamic C# code compilation with `DataTable.Compute()`, a built-in .NET method designed for safe mathematical expression evaluation. This approach:

1. **Eliminates code execution risk**: `DataTable.Compute()` parses expressions as data operations only—it cannot invoke methods, load types, or access the file system.

2. **Validates input rigorously**: The `ValidateExpression()` method enforces a whitelist of safe characters (digits, property names, basic math operators) and blocks injection patterns. This ensures only mathematical formulas are accepted.

3. **Preserves intended functionality**: The evaluator still computes formulas on the `InvoiceSample` properties (`Total`, `Tax`), maintaining the legitimate use case while closing the injection path.

4. **Removes dangerous imports**: Roslyn's `WithImports("System", "System.IO")` is eliminated, preventing access to file I/O and system namespaces.

The expression `"Total + Tax * 0.1"` (for example) is now evaluated safely as a mathematical operation against the sample's property values, not as arbitrary C# code.
