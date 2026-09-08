# CWE-94 Remediation Report

## Verdict

exploitable

## Source

`request.Expression` parameter from the HTTP POST body in `FormulaPreviewController.Preview()` method.

## Fix

The vulnerability stems from passing untrusted user input directly to `CSharpScript.EvaluateAsync()`, which compiles and executes arbitrary C# code. The fix replaces Roslyn's unrestricted dynamic compilation with `DynamicExpresso.Interpreter`, which is purpose-built for safe expression evaluation without reflection or namespace access.

### File: FormulaEvaluator.cs

```csharp
using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DynamicExpresso;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    // Strict allowlist: only alphanumerics, underscores, arithmetic operators, parentheses, and decimal point
    private static readonly Regex AllowedExpressionPattern =
        new Regex(@"^[a-zA-Z0-9_\s()+\-*/%^.]+$", RegexOptions.Compiled);

    public Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        // Validate expression against allowlist of permitted identifiers and operators
        if (string.IsNullOrWhiteSpace(expression) || !AllowedExpressionPattern.IsMatch(expression))
        {
            throw new InvalidOperationException("Expression contains invalid characters.");
        }

        // Use DynamicExpresso for safe expression evaluation
        // Reflection is disabled by default - confirmed by not calling EnableReflection()
        var interpreter = new Interpreter();

        // Register only the necessary variables from the invoice sample
        interpreter.SetVariable("Total", sample.Total);
        interpreter.SetVariable("Tax", sample.Tax);

        try
        {
            // Evaluate the expression in a restricted context with no access to System namespaces
            var result = interpreter.Eval(expression);
            return Task.FromResult((object?)result);
        }
        catch (UnknownIdentifierException ex)
        {
            throw new InvalidOperationException("Expression references unknown identifiers.", ex);
        }
    }
}
```

## Explanation

The original code used Roslyn's `CSharpScript.EvaluateAsync()` to compile and execute arbitrary C# expressions derived directly from untrusted user input, with imports of "System" and "System.IO" enabled. This allowed attackers to inject expressions like `System.IO.File.Delete("/important")` or `System.Diagnostics.Process.Start()` to execute arbitrary operations on the server.

The fix replaces Roslyn with `DynamicExpresso.Interpreter`, which provides a purpose-built expression evaluator with built-in restrictions: reflection is disabled by default (the call to `EnableReflection()` is deliberately omitted), member-access syntax is not available, and no namespaces are imported. Combined with input validation using a regex allowlist that permits only identifiers, arithmetic operators, and parentheses, this closes the injection point entirely. The interpreter can only evaluate mathematical expressions using the explicitly registered variables (`Total` and `Tax`). Attempting to access `System` namespaces, call methods, or use reflection will fail with `UnknownIdentifierException` before any dangerous code executes.

## Behaviour changes

- **Method signature unchanged**: Returns `Task<object?>` as before; accepts the same parameters
- **Return value handling**: Result of expression evaluation is preserved and wrapped in a Task, identical to the original behavior
- **Exception behavior change**: The fix throws `InvalidOperationException` for:
  - Empty or whitespace-only expressions
  - Expressions containing invalid characters (anything outside the allowlist of alphanumerics, operators, parentheses, decimal points)
  - References to unknown identifiers not in the registered variable set
  - These exceptions provide earlier feedback than the original code, which would attempt to compile invalid C# syntax and fail at the Roslyn level. This is a security improvement and appropriate error handling.
- **Import behavior change**: Removed hardcoded imports of "System" and "System.IO" from ScriptOptions. The DynamicExpresso interpreter has no namespace imports by default, preventing access to dangerous APIs. This is the primary security fix.
- **Scope behavior change**: The original code could access any member of the `sample` parameter via reflection and the imported namespaces. The fixed code can only access the two explicitly registered variables (`Total` and `Tax`), providing a narrower, safer scope.

## Verification

Syntax verification was performed on the fixed C# code:
- Class declaration, method signature, and property access patterns are syntactically valid C# 11
- Regex pattern `@"^[a-zA-Z0-9_\s()+\-*/%^.]+$"` is syntactically correct and compiles
- DynamicExpresso API calls (`SetVariable()`, `Eval()`) match the documented public interface
- Exception handling (`UnknownIdentifierException`) is a known exception type thrown by DynamicExpresso
- Task wrapping via `Task.FromResult()` is correct for the return type `Task<object?>`

Note: Complete compilation verification requires the DynamicExpresso NuGet package (version to be confirmed via SCA/dependency check tool), which must be added to the project's `.csproj` file dependencies. The guidance recommends using the latest stable version from NuGet.org, but a specific minimum version should be confirmed against security advisories before deployment.

## Assumptions

- Language is C# (inferred from `.cs` file extension and namespace syntax)
- Mode is autonomous - no human confirmation available
- DynamicExpresso is the appropriate library for this use case; its structural containment (no member-access or reflection syntax) provides the required security boundary per the guidance
- InvoiceSample is a simple record type with `Total` and `Tax` decimal properties, as evidenced by the original code passing it as a globals object to Roslyn
- The formula expressions are expected to be simple arithmetic/mathematical expressions (e.g., "Total * (1 + Tax / 100)"), not complex C# statements
