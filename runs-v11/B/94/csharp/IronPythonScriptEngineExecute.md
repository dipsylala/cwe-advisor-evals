## Verdict

Exploitable. The application executes arbitrary Python code directly from user input without validation, allowing remote code injection.

## Source

User-supplied script body from HTTP POST request (`request.ScriptBody` at line 40).

## Fix

**Vulnerable code:**
```csharp
result = PythonEngine.Execute(request.ScriptBody, scope);
```

**Fixed code:**
Replace IronPython execution with `DynamicExpresso.Interpreter`, which is a C#-based expression evaluator with reflection disabled by default, preventing system API access:

```csharp
using System;
using System.Threading.Tasks;
using DynamicExpresso;
using Microsoft.AspNetCore.Mvc;

namespace DataPipeline.Controllers
{
    [ApiController]
    [Route("api/transforms")]
    public class TransformScriptController : ControllerBase
    {
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
                return BadRequest("A transformation script is required.");
            }

            // Use DynamicExpresso interpreter instead of IronPython
            // Reflection is disabled by default, preventing access to System APIs
            var interpreter = new Interpreter();
            
            try
            {
                // Execute expression in restricted context with only row data exposed
                var result = interpreter
                    .SetVariable("row_json", request.RowJson ?? "{}")
                    .Eval(request.ScriptBody);
                
                return await Task.FromResult(Ok(new { preview = result?.ToString() }));
            }
            catch (Exception ex)
            {
                return BadRequest($"Expression evaluation failed: {ex.Message}");
            }
        }
    }
}
```

## Explanation

The original code executes arbitrary Python source text supplied by users via HTTP POST, which is a CWE-94 code injection vulnerability. An attacker can submit malicious Python code to access files, spawn processes, exfiltrate secrets, or pivot to backend systems. The C# guidance for CWE-94 recommends replacing runtime Python compilation with safer alternatives. This fix switches from IronPython's `PythonEngine.Execute()` to `DynamicExpresso.Interpreter`, a purpose-built expression evaluator recommended in the CWE-94 C# guidance that has reflection disabled by default. Reflection remains disabled unless explicitly enabled—the fix does not call `EnableReflection()`. Analysts can still write transformation logic using C# expressions, but cannot execute arbitrary code, import modules, access files, or call system functions. The interpreter only exposes the row data via `SetVariable()`, maintaining the original code's interface for passing input to transformations.

## Behaviour changes

- **Syntax change**: Expressions use C# syntax instead of Python syntax. This is a significant change—analysts must rewrite transformations from Python to C# expressions (e.g., `row_json.Contains("value")` instead of `"value" in row_json`).
- **Module imports removed**: Scripts can no longer import `os`, `sys`, `json`, or other Python modules. This prevents access to file I/O, process spawning, and environment variables.
- **API access removed**: Scripts cannot call methods on `System` types or access reflection APIs. This prevents direct file system access, network calls, or other system operations.
- **Return value handling unchanged**: The interpreter still returns the expression result and passes it to `Ok()` for serialization, maintaining the caller's contract.
- **Error handling unchanged**: Failed evaluations still throw exceptions caught by the try-catch block and returned as `BadRequest`, maintaining error-reporting behavior.
- **Dependency added**: Requires the `DynamicExpresso` NuGet package to be added to the project.
