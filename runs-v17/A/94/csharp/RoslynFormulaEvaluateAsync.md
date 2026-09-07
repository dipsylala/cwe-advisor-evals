## Verdict
VULNERABLE. The expression parameter passes untrusted user input directly to CSharpScript.EvaluateAsync() without validation, enabling arbitrary C# code execution despite restricted imports.

## Source
FormulaPreviewController.Preview() receives user input (request.Expression) via HTTP POST and passes it to FormulaEvaluator.EvaluateAsync(). At line 14 of FormulaEvaluator.cs, this expression is evaluated as C# code without validation. An attacker can craft expressions using fully qualified names (e.g., System.Diagnostics.Process.Start()) that bypass the restricted imports, achieving remote code execution.

## Fix
### File: FormulaEvaluator.cs
```csharp
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using System.Text.RegularExpressions;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    // Whitelist of characters allowed in formula expressions (numeric operations and property access only)
    private static readonly Regex SafeFormulaPattern = new(
        @"^[a-zA-Z0-9_\s\(\)\+\-\*/%\.\,]+$",
        RegexOptions.Compiled
    );

    // Keywords that indicate code injection attempts
    private static readonly string[] BlockedKeywords = new[]
    {
        "typeof", "new", "namespace", "class", "interface", "struct", "enum",
        "static", "using", "delegate", "event", "lambda", "=>"
    };

    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        // Input validation: empty or null check
        if (string.IsNullOrWhiteSpace(expression))
        {
            throw new ArgumentException("Expression cannot be null or empty", nameof(expression));
        }

        // Input validation: length limit to prevent resource exhaustion
        if (expression.Length > 256)
        {
            throw new ArgumentException("Expression exceeds maximum length of 256 characters", nameof(expression));
        }

        // Input validation: character whitelist
        if (!SafeFormulaPattern.IsMatch(expression))
        {
            throw new ArgumentException("Expression contains invalid characters", nameof(expression));
        }

        // Input validation: block dangerous keywords and fully qualified names
        var lowerExpression = expression.ToLowerInvariant();
        foreach (var keyword in BlockedKeywords)
        {
            if (lowerExpression.Contains(keyword))
            {
                throw new ArgumentException($"Expression contains disallowed keyword: {keyword}", nameof(expression));
            }
        }

        // Additional block on common injection patterns
        if (lowerExpression.Contains("system.") || 
            lowerExpression.Contains("process") || 
            lowerExpression.Contains("file") ||
            lowerExpression.Contains("directory") ||
            lowerExpression.Contains("reflection") ||
            lowerExpression.Contains("assembly"))
        {
            throw new ArgumentException("Expression contains disallowed namespace or type access", nameof(expression));
        }

        var options = ScriptOptions.Default
            .WithImports("System")
            .WithReferences(typeof(InvoiceSample).Assembly);

        return CSharpScript.EvaluateAsync(expression, options, sample);
    }
}
```

## Explanation
The vulnerability occurs because Roslyn's CSharpScript.EvaluateAsync() evaluates arbitrary C# code. Even when imports are restricted, attackers can use fully qualified type names to access dangerous APIs. The fix implements defense-in-depth validation:

1. **Input length limit** (256 chars) prevents resource exhaustion attacks and signals this is for simple formulas only.
2. **Character whitelist** (alphanumerics, operators, dots, parentheses, commas) ensures the expression structurally resembles a formula, blocking syntax for class definitions, lambdas, and other code constructs.
3. **Keyword blocklist** prevents instantiation (`new`), type introspection (`typeof`), and code structure keywords.
4. **Namespace/type blocklist** explicitly rejects fully qualified names and common injection targets like `System.Diagnostics.Process`, `System.IO.File`, and reflection APIs.
5. **Removed System.IO import** which was unnecessary for formula evaluation and expanded the attack surface.

This approach validates at the boundary before code reaches Roslyn, ensuring only safe formula expressions are evaluated against the provided sample object.
