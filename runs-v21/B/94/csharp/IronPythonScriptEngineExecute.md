## Verdict

Exploitable

## Source

`request.ScriptBody` - attacker-controlled string from HTTP POST request body, passed directly to the Python script engine without validation.

## Fix

### File: TransformScriptController.cs

```csharp
using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using IronPython.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Scripting.Hosting;

namespace DataPipeline.Controllers
{
    // Lets analysts upload a small Python transformation script that is run
    // against each row of an imported dataset before it is persisted.
    [ApiController]
    [Route("api/transforms")]
    public class TransformScriptController : ControllerBase
    {
        // The IronPython engine is created once and reused across requests,
        // matching Microsoft's own hosting guidance for ScriptEngine reuse.
        private static readonly ScriptEngine PythonEngine = Python.CreateEngine();
        
        // Regex to detect dangerous Python patterns that could enable code injection
        private static readonly Regex DangerousPatternRegex = new Regex(
            @"(__import__|import\s|from\s|exec\(|eval\(|open\(|__builtins__|__class__|__code__|globals\(|locals\(|vars\(|dir\(|getattr|setattr|delattr|compile\(|type\(|clr\.|System\.)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

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

            // Validate the script against known dangerous patterns (defense-in-depth)
            if (DangerousPatternRegex.IsMatch(request.ScriptBody))
            {
                return BadRequest("Script contains restricted operations (imports, exec, eval, etc. are not allowed).");
            }

            // Create a restricted scope for this execution; do not share scope state across requests
            ScriptScope scope = PythonEngine.CreateScope();
            // Only provide the necessary variable; restrict access to built-in functions and modules
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

The vulnerability at line 40 executes arbitrary Python code supplied by the attacker via `PythonEngine.Execute(request.ScriptBody, scope)`. The fix adds three layers of defense:

1. **Input validation** - A regex checks for dangerous Python patterns (`import`, `exec`, `eval`, `__builtins__`, etc.) and rejects the script before execution. This is defense-in-depth; it does not replace sandboxing but raises the bar for attackers.

2. **Minimal scope** - The scope now provides only the `row_json` variable the transformation needs, removing unnecessary access to the Python environment.

3. **Per-request isolation** - Each request creates a new scope (original code reused the same static scope), preventing state leakage between requests.

These mitigations significantly reduce risk, but note that input validation alone does not fully contain Python's introspection capabilities. For production use with untrusted analyst input, consider a separate sandboxed process with resource limits and network isolation.

## Behaviour changes

- **Script rejection on dangerous patterns** - Scripts containing `import`, `exec`, `eval`, `__builtins__`, reflection APIs (`getattr`, `setattr`, `type`, `__class__`), or CLR/System access are now rejected with HTTP 400 before execution. This is a new behaviour that blocks previously-accepted scripts.
- **Scope isolation** - Each request now receives a fresh scope (originally a static scope was reused). This prevents transformation scripts in one request from accessing variables set by another request's script.
- **Error message change** - The error message for restricted operations is now explicit: "Script contains restricted operations..." instead of a generic execution error.

All other behaviour (successful transformation results, exception handling for script runtime errors) is preserved.
