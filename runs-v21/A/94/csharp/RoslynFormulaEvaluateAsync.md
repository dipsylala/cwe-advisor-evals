## Verdict
Confirmed. The `EvaluateAsync()` method accepts user-controlled expression input and passes it directly to `CSharpScript.EvaluateAsync()` without validation or restriction, enabling arbitrary C# code execution.

## Source
- **File:** FormulaPreviewController.cs
- **Data flow:** HTTP POST request `FormulaPreviewRequest.Expression` → `FormulaEvaluator.EvaluateAsync(expression, ...)` → `CSharpScript.EvaluateAsync(expression, options, sample)`
- **Sink:** `CSharpScript.EvaluateAsync()` on line 14 of FormulaEvaluator.cs

## Fix

### File: FormulaEvaluator.cs
```csharp
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using System.Text.RegularExpressions;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    private static readonly Regex AllowedExpressionPattern = new(
        @"^[\d\s\+\-\*/\(\)\.\,]+$",
        RegexOptions.Compiled
    );

    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        if (string.IsNullOrWhiteSpace(expression))
            throw new ArgumentException("Expression cannot be empty.", nameof(expression));

        if (!AllowedExpressionPattern.IsMatch(expression))
            throw new ArgumentException("Expression contains disallowed characters.", nameof(expression));

        var options = ScriptOptions.Default
            .WithImports("System")
            .WithReferences(typeof(InvoiceSample).Assembly);

        return CSharpScript.EvaluateAsync(expression, options, sample);
    }
}
```

## Explanation
The fix applies three key controls:

1. **Removed System.IO import** - Eliminates the primary vector for file system access and other dangerous operations. The expression evaluator retains only `System` namespace for basic math/type operations needed for formula evaluation.

2. **Input validation with allowlist** - A regex pattern restricts expressions to only numeric literals, whitespace, and mathematical operators (`+`, `-`, `*`, `/`, parentheses, and decimal points). This prevents method invocation, type access, and other code constructs that enable exploitation.

3. **Null/empty check** - Rejects empty input before evaluation.

These controls ensure that only safe arithmetic expressions can be evaluated. An attacker attempting to inject code like `System.IO.File.ReadAllText()` or invoke arbitrary methods will be rejected at the validation boundary before reaching the script engine.
