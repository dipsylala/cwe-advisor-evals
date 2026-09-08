## Verdict

Exploitable. The `reportName` parameter from the HTTP form is concatenated directly into the command arguments string without any parameterization. Even though `UseShellExecute = false` is set, the target is a `.bat` file, which Windows executes through `cmd.exe`, causing cmd.exe to re-parse the entire command line. An attacker can inject arbitrary commands using special characters like `&`, `|`, `>`, or `;`. For example, passing `reportName = "test" & del C:\*.*` would cause the deletion of files in addition to generating the report.

## Source

The vulnerability originates from user-supplied input in the HTTP POST parameter `reportName` (via `[FromForm] string reportName` on line 20), which is directly concatenated into the `ProcessStartInfo.Arguments` property on line 27 without any validation or parameterization.

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
                ArgumentList = { "-report", reportName },
                UseShellExecute = false,
                RedirectStandardOutput = true,
                WorkingDirectory = _scriptsDir
            };

            using var process = Process.Start(psi);

            string output = process!.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return Content(output, "text/plain");
        }
    }
}
```

## Explanation

The fix replaces string concatenation (`Arguments = "-report " + reportName`) with the parameterized `ArgumentList` property. `ArgumentList` is a `List<string>` that passes each argument as a separate token, with proper quoting and escaping by .NET. This prevents the shell from interpreting special characters in the user-supplied `reportName` as command operators. Even though the target is a `.bat` file that Windows internally routes through `cmd.exe`, the properly quoted arguments passed through `ArgumentList` prevent cmd.exe from re-parsing the command and injecting additional commands. The arguments preserve the same semantics as the original code (the batch file receives `-report` as one argument and the report name as the second), but through a safe mechanism that prevents injection.

## Behaviour changes

None. The batch file receives the same arguments in the same order. The `-report` parameter is passed as the first argument and the user-supplied report name as the second argument, identical to the original code's intent. The only change is the mechanism by which arguments are passed: through a structured argument list rather than a concatenated string. No additional input validation or processing is introduced, and the return value and output handling remain unchanged.
