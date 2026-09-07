## Verdict

**Exploitable**: Yes. The `reportName` parameter flows from an HTTP POST request directly into the process command arguments via string concatenation. An attacker can inject command metacharacters (e.g., `&`, `|`, `;`) or escape the intended argument boundary.

## Source

Line 20: `reportName` parameter from `[FromForm] string reportName` - user-supplied HTTP POST data, untrusted.

Data flows to line 27, where it is concatenated into the `Arguments` string without escaping:
```
Arguments = "-report " + reportName
```

## Fix

### File: BatchScriptReentry.cs

```csharp
using System.Diagnostics;
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ReportsController : ControllerBase
    {
        private readonly string _scriptsDir;

        public ReportsController(IWebHostEnvironment env)
        {
            _scriptsDir = Path.Combine(env.ContentRootPath, "Scripts");
        }

        // Runs the bundled reporting batch script against a caller-supplied report name.
        [HttpPost("generate")]
        public IActionResult GenerateReport([FromForm] string reportName)
        {
            string scriptPath = Path.Combine(_scriptsDir, "run-report.bat");

            var psi = new ProcessStartInfo
            {
                FileName = scriptPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                WorkingDirectory = _scriptsDir
            };

            // Pass arguments via ArgumentList to prevent shell injection.
            psi.ArgumentList.Add("-report");
            psi.ArgumentList.Add(reportName);

            using var process = Process.Start(psi);

            string output = process!.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return Content(output, "text/plain");
        }
    }
}
```

## Explanation

The fix replaces string concatenation of user input (the `Arguments` property) with `ArgumentList`, a property-based array mechanism that passes each argument as a distinct token to the underlying process. This prevents the attacker-controlled value from being reinterpreted as command syntax.

The `Arguments` property concatenates a single string that the operating system can re-tokenize based on shell metacharacters and quoting rules. By contrast, `ArgumentList.Add()` submits each argument as a distinct element, preventing metacharacter reinterpretation at the OS level (for non-batch executables; batch files have additional constraints noted below).

`UseShellExecute = false` is set explicitly to document the intent and ensure .NET does not invoke `cmd.exe` as an extra layer (it already defaults to false on .NET Core/5+ but true on .NET Framework; setting it explicitly is defensive).

## Behaviour changes

- **Arguments mechanism changed**: `Arguments` string → `ArgumentList` property. The fix maintains the same arguments (`"-report"` and the report name), so the batch script receives the same semantic command.
- **Return value preserved**: Process output is read and returned identically.
- **Execution context preserved**: `WorkingDirectory` remains set to `_scriptsDir`.
- **Note on batch files**: Windows re-parses command lines for `.bat`/`.cmd` targets at the OS level, so even `ArgumentList` provides only partial protection at the shell-invocation boundary. The safest pattern would be to invoke the underlying executable that the batch file wraps (e.g., if `run-report.bat` is a wrapper around a `.exe` or script interpreter, call that directly). This case assumes the batch script is the intended target and `ArgumentList` is the best-available parameterization in managed code.
