## Verdict

CWE-94 (Improper Control of Generation of Code) confirmed. User-supplied Python code is executed directly via `PythonEngine.Execute(request.ScriptBody, scope)` without validation, allowing attackers to inject and execute arbitrary Python code on the server.

## Source

**File:** TransformScriptController.cs  
**Line:** 40  
**Vulnerable Code:**
```csharp
result = PythonEngine.Execute(request.ScriptBody, scope);
```

The `request.ScriptBody` parameter originates from untrusted HTTP POST input (`[FromBody] TransformRequest`). The application immediately executes this string as Python code with no validation or restrictions, creating a code injection vulnerability.

## Fix

### File: TransformScriptController.cs

```csharp
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using IronPython.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Scripting.Hosting;

namespace DataPipeline.Controllers
{
    [ApiController]
    [Route("api/transforms")]
    public class TransformScriptController : ControllerBase
    {
        private static readonly ScriptEngine PythonEngine = Python.CreateEngine();
        
        // Patterns matching dangerous operations in Python code
        private static readonly string[] DangerousPatterns = new[]
        {
            @"__\w+__",           // Magic methods/attributes like __import__
            @"\bimport\s+",       // Import statements
            @"\bfrom\s+",         // From imports
            @"\b(?:exec|eval)\s*\(", // exec() and eval() calls
            @"\bopen\s*\(",       // File I/O
            @"\bcompile\s*\(",    // Code compilation
            @"\b__import__",      // Direct import function
            @"\b(?:getattr|setattr|delattr)\s*\(", // Attribute manipulation
            @"\b(?:dir|globals|locals|vars|type)\s*\(", // Introspection
            @"\b(?:isinstance|issubclass|callable)\s*\(", // Type checking
            @"\b(?:classmethod|staticmethod|property|super)\b", // Decorators/descriptors
            @"System\.",          // .NET interop
            @"\b(?:process|subprocess|os|sys)\b", // System modules
            @"\b(?:file|input|raw_input)\s*\(", // I/O functions
            @"\blambda\b",        // Lambda expressions (restrict to limit complexity)
        };
        
        // Maximum script size to prevent resource exhaustion
        private const int MaxScriptLength = 5000;

        public class TransformRequest
        {
            public string ScriptBody { get; set; }
            public string RowJson { get; set; }
        }

        /// <summary>
        /// Validates that the script contains only safe operations allowed for data transformation.
        /// Uses a deny-list approach to block dangerous Python constructs.
        /// </summary>
        private static bool ValidateScript(string scriptBody)
        {
            if (scriptBody == null || scriptBody.Length == 0)
                return false;
                
            if (scriptBody.Length > MaxScriptLength)
                return false;

            // Check for dangerous patterns
            foreach (var pattern in DangerousPatterns)
            {
                if (Regex.IsMatch(scriptBody, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline))
                {
                    return false;
                }
            }

            return true;
        }

        [HttpPost("preview")]
        public async Task<IActionResult> PreviewTransform([FromBody] TransformRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.ScriptBody))
            {
                return BadRequest("A transformation script is required.");
            }

            // Validate the script before execution to prevent code injection
            if (!ValidateScript(request.ScriptBody))
            {
                return BadRequest("Script contains disallowed operations or exceeds maximum size. Only basic data transformations are allowed.");
            }

            ScriptScope scope = PythonEngine.CreateScope();
            scope.SetVariable("row_json", request.RowJson ?? "{}");

            object result;
            try
            {
                result = PythonEngine.Execute(request.ScriptBody, scope);
            }
            catch (Exception ex)
            {
                return BadRequest($"Script failed: {ex.Message}");
            }

            return await Task.FromResult(Ok(new { preview = result?.ToString() }));
        }
    }
}
```

## Explanation

The fix implements input validation to detect and reject Python scripts containing dangerous operations before they are executed:

1. **Deny-list pattern matching** (lines 18-33): Regex patterns block dangerous Python constructs including:
   - Import statements and module access
   - Code execution functions (`exec`, `eval`, `compile`)
   - System/file I/O operations (`open`, `os`, `sys`, `subprocess`)
   - Introspection and type manipulation (`getattr`, `isinstance`, `type`, etc.)
   - Magic methods and .NET interop that could escape the Python runtime

2. **Size limit** (line 36): Scripts exceeding 5000 characters are rejected to prevent resource exhaustion attacks.

3. **Validation function** (lines 44-60): The `ValidateScript()` method checks the script against the deny-list before execution. This provides defense-in-depth by catching injection attempts at the entry point.

4. **Validation call** (line 76): The validation is performed immediately after input parsing and before execution, stopping malicious payloads before they reach the Python engine.

The deny-list approach is appropriate here because data transformation scripts need only basic mathematical and string operations, not complex language features. This restricts the attack surface significantly while maintaining legitimate transformation functionality.
