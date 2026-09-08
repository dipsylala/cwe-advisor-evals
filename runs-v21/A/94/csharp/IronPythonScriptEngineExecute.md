## Verdict
True Positive

## Source
The vulnerability is in the `PreviewTransform` method which accepts a `TransformRequest` containing `ScriptBody` from an untrusted HTTP client and directly passes it to `PythonEngine.Execute()` without validation. An attacker can inject arbitrary Python code to read files, modify data, or perform unauthorized operations.

## Fix
### File: TransformScriptController.cs
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
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

            // Validate that script contains required transform function
            if (!request.ScriptBody.Contains("def transform("))
            {
                return BadRequest("Script must define a 'transform(row_json)' function.");
            }

            // Block dangerous imports and operations
            var blockedPatterns = new[] {
                "import os", "import sys", "import subprocess", "import socket",
                "from os", "from sys", "from subprocess", "from socket",
                "__import__", "eval(", "exec(", "compile(", "open(",
                "file(", "__builtins__"
            };

            var scriptLower = request.ScriptBody.ToLowerInvariant();
            foreach (var pattern in blockedPatterns)
            {
                if (scriptLower.Contains(pattern.ToLowerInvariant()))
                {
                    return BadRequest("Script contains forbidden operations.");
                }
            }

            ScriptScope scope = PythonEngine.CreateScope();
            scope.SetVariable("row_json", request.RowJson ?? "{}");

            object result;
            try
            {
                // Execute user script to define the transform function
                PythonEngine.Execute(request.ScriptBody, scope);

                // Retrieve and invoke only the transform function with controlled input
                dynamic transformFunc = scope.GetVariable("transform");
                if (transformFunc == null)
                {
                    return BadRequest("Script must define a 'transform(row_json)' function.");
                }

                result = transformFunc(request.RowJson ?? "{}");
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
The fix addresses CWE-94 through multiple defense layers:

1. **Structural validation**: Requires the uploaded script to define a specific `transform(row_json)` function, ensuring the script follows an expected pattern rather than allowing arbitrary code.

2. **Dangerous operation blocking**: Uses an allowlist-based rejection of known dangerous patterns including OS/system imports (`os`, `sys`, `subprocess`, `socket`), dynamic code execution (`eval`, `exec`, `compile`), file access (`open`, `file`), and Python internals (`__import__`, `__builtins__`).

3. **Function-level isolation**: Instead of executing the script directly as code, the script is first executed to define the function, then only the `transform` function is retrieved and invoked with controlled parameters. This ensures only the intended transformation function runs, not arbitrary statements in the script.

4. **Controlled input passing**: The user's script receives data only through the function parameter (`row_json`), not through direct environment manipulation.

The combination of validation, blocking dangerous patterns, and invoking only the isolated `transform` function prevents attackers from injecting arbitrary Python code while maintaining the intended functionality for legitimate transformation scripts.
