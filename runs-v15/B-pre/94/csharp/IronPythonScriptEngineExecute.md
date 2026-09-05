## Verdict

**CONFIRMED** — CWE-94 (Improper Control of Generation of Code - Code Injection) at line 40. The `request.ScriptBody` parameter flows untrusted user input directly into `PythonEngine.Execute()` without validation or containment. No amount of ScriptScope restriction provides a sandbox against reflection and introspection attacks. The IronPython engine, like all dynamic language runtimes in .NET, has no built-in isolation mechanism.

## Source

Line 40 in `TransformScriptController.cs`:
```csharp
result = PythonEngine.Execute(request.ScriptBody, scope);
```

The `request.ScriptBody` originates from the HTTP POST body (`TransformRequest.ScriptBody`), which is attacker-controlled. The ScriptScope created at line 33 restricts only the initial variables, not the engine's capabilities - Python's reflection APIs (`__import__`, `__loader__`, type introspection via `__class__.__bases__`) can escape any variable-level restriction.

## Fix

Replace arbitrary code execution with a predefined transformation dispatch table. This removes the attack surface entirely:

```csharp
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace DataPipeline.Controllers
{
    [ApiController]
    [Route("api/transforms")]
    public class TransformScriptController : ControllerBase
    {
        // Predefined, audited transformation functions
        private static readonly Dictionary<string, Func<string, string>> AllowedTransforms =
            new(StringComparer.OrdinalIgnoreCase)
            {
                { "uppercase", json => json?.ToUpper() ?? "" },
                { "lowercase", json => json?.ToLower() ?? "" },
                { "reverse", json => json != null ? new string(json.Reverse().ToArray()) : "" },
                { "trim", json => json?.Trim() ?? "" }
            };

        public class TransformRequest
        {
            public string ScriptName { get; set; }  // Changed: now a transformation name, not code
            public string RowJson { get; set; }
        }

        [HttpPost("preview")]
        public async Task<IActionResult> PreviewTransform([FromBody] TransformRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.ScriptName))
            {
                return BadRequest("A transformation name is required.");
            }

            if (!AllowedTransforms.TryGetValue(request.ScriptName, out var transform))
            {
                return BadRequest($"Unknown transformation: {request.ScriptName}. Allowed: {string.Join(", ", AllowedTransforms.Keys)}");
            }

            string result;
            try
            {
                // Invoke only the whitelisted transformation
                result = transform(request.RowJson ?? "{}");
            }
            catch (Exception ex)
            {
                return BadRequest($"Transform failed: {ex.Message}");
            }

            return await Task.FromResult(Ok(new { preview = result }));
        }
    }
}
```

**Alternative if flexible expressions are required:** If the application genuinely needs user-supplied expressions (not arbitrary code), use `DynamicExpresso.Interpreter` with reflection disabled (the default) and no `Reference()` to reflection-exposing types:

```csharp
using DynamicExpresso;

public async Task<IActionResult> PreviewTransform([FromBody] TransformRequest request)
{
    if (string.IsNullOrWhiteSpace(request?.ScriptBody))
        return BadRequest("An expression is required.");

    var interpreter = new Interpreter();
    interpreter.SetVariable("row", request.RowJson ?? "{}");
    // Explicitly do NOT call EnableReflection() - it remains off by default
    // Explicitly do NOT Reference() System or user types - they cannot be invoked

    try
    {
        // DynamicExpresso interprets only arithmetic, boolean, and string operations
        // It has no access to method calls, reflection, or type instantiation
        var result = interpreter.Eval(request.ScriptBody);
        return await Task.FromResult(Ok(new { preview = result?.ToString() }));
    }
    catch (Exception ex)
    {
        return BadRequest($"Expression failed: {ex.Message}");
    }
}
```

## Explanation

The first fix (predefined transformations) eliminates code injection entirely by replacing dynamic execution with a static dispatch table of audited functions. Users select a transformation by name; they cannot supply code. The second fix (if expressions must be flexible) constrains evaluation to DynamicExpresso's built-in expression language, which has no member access, reflection, or metaprogramming syntax—attackers cannot invoke `System.IO.File.Delete()` or any other method, regardless of what string they supply. Both approaches close the CWE-94 attack surface: no user input reaches code execution.

The key difference from the original: `PythonEngine.Execute()` is removed entirely. A ScriptScope with restricted variables does not provide containment—Python's `__class__`, `__bases__`, and import mechanisms traverse the namespace hierarchy to reach dangerous types. Per the remediation guidance, the only reliable isolation is a separate process with restricted OS-level permissions, which is architecturally unavailable here. Removing dynamic execution is the appropriate fix.

## Behaviour changes

- **Input interface**: The API now expects `"scriptName"` (a transformation identifier) instead of `"scriptBody"` (Python source code). The client must send `{ "scriptName": "uppercase", "rowJson": "..." }` rather than `{ "scriptBody": "...", "rowJson": "..." }`.
- **Error handling**: Invalid transformation names return 400 with a list of allowed names. Malformed expressions in the DynamicExpresso variant return 400 with the expression error. Both are more specific than the original catch-all exception.
- **Output**: Transformations now return strings. The original `result?.ToString()` is replaced with the direct string result from the chosen function or evaluated expression.
- **Security**: Arbitrary code execution is impossible. Only the whitelisted operations (or safe expressions in the DynamicExpresso variant) can run.
