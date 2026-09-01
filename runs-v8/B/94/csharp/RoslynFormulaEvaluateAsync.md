## Verdict

Exploitable. The `expression` parameter flows unvalidated from user input directly to `CSharpScript.EvaluateAsync()` at line 14. The `ScriptOptions` configuration exposes `System.IO` namespace, permitting arbitrary file and process operations. No allowlist or input validation exists to restrict what code executes.

## Source

The `expression` parameter passed to the `EvaluateAsync` method at line 8 is user-controlled and untrusted.

## Fix

**Vulnerable code (line 14):**
```csharp
return CSharpScript.EvaluateAsync(expression, options, sample);
```

**Fixed code:**
```csharp
using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    private static readonly Dictionary<string, Func<InvoiceSample, object?>> AllowedFormulas =
        new Dictionary<string, Func<InvoiceSample, object?>>(StringComparer.OrdinalIgnoreCase)
        {
            { "TaxAmount", sample => sample.TaxAmount },
            { "Total", sample => sample.Total },
            { "Subtotal", sample => sample.Subtotal }
        };

    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        if (!AllowedFormulas.TryGetValue(expression, out var formula))
        {
            throw new ArgumentException($"Formula '{expression}' is not allowed.", nameof(expression));
        }

        var result = formula(sample);
        return System.Threading.Tasks.Task.FromResult(result);
    }
}
```

## Explanation

The fix replaces dynamic code compilation with a dispatch table containing only predefined, safe formula operations. The `AllowedFormulas` dictionary maps formula names to compiled delegates that safely access `InvoiceSample` properties. When `EvaluateAsync` is called, the expression is looked up in the dictionary; if it matches a known formula, the corresponding delegate executes with controlled access to only the intended properties. If the expression is not in the allowlist, an `ArgumentException` is thrown immediately. This eliminates the code injection vulnerability by removing the dynamic compilation path entirely and enforcing a strict allowlist of permitted operations. The method signature remains unchanged, maintaining compatibility with existing callers.

## Behaviour changes

- **Restricted input**: Only formula names in `AllowedFormulas` are accepted; any other input throws `ArgumentException` instead of executing arbitrary code.
- **Execution model**: Formulas are evaluated immediately (synchronous) rather than compiled and executed asynchronously, but wrapped in a completed `Task<object?>` to preserve the async interface.
- **Return type consistency**: Results are boxed as `object?` to match the original interface; properties must return compatible types or be wrapped appropriately.
- **No namespace access**: `System` and `System.IO` imports are removed; formulas cannot access file operations, reflection, or other system APIs.
- **Error handling**: Rejections occur at the allowlist check, not during runtime compilation, surfacing invalid inputs immediately with a clear error message.
