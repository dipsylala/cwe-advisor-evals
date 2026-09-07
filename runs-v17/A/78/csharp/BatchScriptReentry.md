## Verdict
**Confirmed** – CWE-78 (OS Command Injection)

## Source
User-supplied `reportName` parameter from `[FromForm]` is concatenated directly into the process arguments without validation or escaping. When passed to a batch file via `ProcessStartInfo`, special batch interpreter characters (`%`, `^`, `!`, `&`, `|`, `;`, etc.) can be misinterpreted as commands or operators, leading to command injection.

## Fix

### File: BatchScriptReentry.cs

```csharp
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
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
            // Validate reportName to allow only safe characters: alphanumerics, hyphens, underscores
            if (string.IsNullOrEmpty(reportName) || !Regex.IsMatch(reportName, @"^[a-zA-Z0-9_-]+$"))
            {
                return BadRequest("Invalid report name. Only alphanumerics, hyphens, and underscores are allowed.");
            }

            string scriptPath = Path.Combine(_scriptsDir, "run-report.bat");

            var psi = new ProcessStartInfo
            {
                FileName = scriptPath,
                Arguments = "-report " + reportName,
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
The fix adds input validation using a regex allowlist that restricts `reportName` to only alphanumerics, hyphens, and underscores. This prevents injection of batch metacharacters like `%`, `^`, `!`, `&`, `|`, `;`, `<`, `>`, and `"`. If the input fails validation, the endpoint returns a `BadRequest` response, ensuring the unsanitized value never reaches the process. This approach is more robust than escaping because batch syntax has multiple levels of interpretation and allowlisting the safe character set is the primary defense for this scenario.
