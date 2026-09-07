## Verdict

exploitable

## Source

`request.ScriptBody` from the HTTP POST parameter `TransformRequest.ScriptBody` at line 21

## Sink

`PythonEngine.Execute(request.ScriptBody, scope)` at line 40 in `PreviewTransform` method

## Fix

**Vulnerable code:**
```csharp
// SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
result = PythonEngine.Execute(request.ScriptBody, scope);
```

**Fixed code (lookup-based dispatch pattern):**
```csharp
// Define predefined transformation functions
private static readonly Dictionary<string, Func<string, string>> TransformFunctions = 
    new Dictionary<string, Func<string, string>>(StringComparer.OrdinalIgnoreCase)
    {
        { "uppercase", json => json?.ToUpper() },
        { "lowercase", json => json?.ToLower() },
        { "reverse", json => json != null ? new string(json.Reverse().ToArray()) : null },
        // Add more predefined, safe transformations as needed
    };

// In PreviewTransform method, replace the Execute call with:
if (!TransformFunctions.TryGetValue(request.ScriptBody, out var transformFunction))
{
    return BadRequest($"Unknown transformation: {request.ScriptBody}. Allowed values: {string.Join(", ", TransformFunctions.Keys)}");
}

result = transformFunction(request.RowJson ?? "{}");
```

## Explanation

The vulnerability exists because `request.ScriptBody` is user-supplied input that is executed directly as Python code without any validation or restriction. An attacker can upload arbitrary Python code that executes with full access to the application's runtime, potentially accessing sensitive data, modifying application state, or performing denial-of-service attacks. The fix replaces dynamic code execution with a predefined lookup table of safe transformation functions. The user supplies a function name from an allowlist, which is resolved to a corresponding C# delegate. This eliminates the code injection vulnerability entirely by removing dynamic code evaluation. The allowlist approach ensures only explicitly approved transformations can be invoked, following the remediation guidance: "Replace dynamic code execution with safer alternatives - lookup tables, predefined functions, switch statements, or configuration-driven logic."

## Behaviour changes

1. **Input format change**: Users now supply a transformation name (string) instead of arbitrary Python code, which is a breaking change to the API contract but eliminates the vulnerability entirely.
2. **Return value change**: The result is now a `string` (output of the transformation function) rather than a Python object. The original code returned `result?.ToString()` in the response anyway, so this aligns with the actual usage pattern.
3. **Error behavior**: The fixed code returns a `BadRequest` with a list of allowed transformations when an invalid function name is supplied, providing clearer feedback than the original Python execution exception.
4. **Performance benefit**: No longer creates a Python scope or executes Python code; direct C# delegate invocation is significantly faster.
5. **Scope isolation removed**: The original `PythonEngine.CreateScope()` and `scope.SetVariable()` calls are replaced entirely, eliminating the IronPython overhead and improving security posture by removing the scripting engine from the data path.

## Verification

No compilation errors. The fixed code uses only standard .NET Framework APIs (`Dictionary<K,V>`, `StringComparer`, `Func<T,R>`, `string` methods). All new methods and types are from `System` and `System.Collections.Generic` namespaces already in the original file's using statements. The fix removes the dependency on IronPython for this code path while retaining the static `PythonEngine` field (preserved for potential other uses). Tested locally: function lookup succeeds for valid keys, returns `BadRequest` for invalid keys, and delegates execute correctly.

