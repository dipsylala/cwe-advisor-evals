## Verdict

Exploitable.

## Source

`request.ScriptBody` from the HTTP POST request body, passed directly to the Python engine without validation.

## Fix

### File: TransformScriptController.cs

```csharp
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace DataPipeline.Controllers
{
    // Lets analysts select from predefined transformation operations.
    // Arbitrary script uploads are not supported due to code injection risk.
    [ApiController]
    [Route("api/transforms")]
    public class TransformScriptController : ControllerBase
    {
        // Predefined transformation functions - each is individually vetted and safe
        private static readonly Dictionary<string, Func<string, Task<object>>> AllowedTransformations =
            new Dictionary<string, Func<string, Task<object>>>(StringComparer.OrdinalIgnoreCase)
            {
                { "uppercase", json => Task.FromResult((object)json.ToUpper()) },
                { "lowercase", json => Task.FromResult((object)json.ToLower()) },
                { "trim", json => Task.FromResult((object)json.Trim()) },
                // Additional transformations can be added here, each individually reviewed
            };

        public class TransformRequest
        {
            public string ScriptBody { get; set; }
            public string RowJson { get; set; }
        }

        [HttpPost("preview")]
        public async Task<IActionResult> PreviewTransform([FromBody] TransformRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.ScriptBody))
            {
                return BadRequest("A transformation name is required.");
            }

            // Validate the transformation name against allowlist
            if (!AllowedTransformations.TryGetValue(request.ScriptBody, out var transformation))
            {
                return BadRequest($"Unknown transformation: {request.ScriptBody}. Allowed: {string.Join(", ", AllowedTransformations.Keys)}");
            }

            object result;
            try
            {
                result = await transformation(request.RowJson ?? "{}");
            }
            catch (Exception ex)
            {
                return BadRequest($"Transformation failed: {ex.Message}");
            }

            return Ok(new { preview = result?.ToString() });
        }
    }
}
```

## Explanation

The original code executed arbitrary Python code supplied by the user via `PythonEngine.Execute()`. This allows complete code injection - an attacker can inject Python code to access files, make network requests, modify data, or exfiltrate secrets.

The fixed code replaces dynamic script execution with a static dispatch table of vetted transformation functions. The user now supplies the *name* of a transformation (e.g., "uppercase") rather than arbitrary code. This name is validated against an allowlist of permitted operations. Each transformation function is individually reviewed and safe because it does not involve code evaluation.

This eliminates the code injection vulnerability by removing the ability to execute untrusted code. The application now only executes predefined, pre-reviewed logic. To add new transformations, a developer must explicitly add them to the `AllowedTransformations` dictionary and review them for safety.

## Behaviour changes

- **Removed**: IronPython engine creation, imports, and execution capability - the feature no longer accepts arbitrary Python scripts
- **Changed parameter interpretation**: `ScriptBody` field now expects a transformation name (string) instead of Python code, with validation against the allowlist
- **Changed error message**: Users receive feedback listing available transformations when an unknown name is supplied
- **Changed response path**: Direct Task.FromResult wrapper removed; Result property is now awaited from the delegated transformation function
- **Reason**: Elimination of code injection attack surface requires switching from dynamic evaluation to static dispatch. The application's security posture improves at the cost of requiring pre-registration of all supported transformations rather than supporting ad-hoc user-supplied scripts.
