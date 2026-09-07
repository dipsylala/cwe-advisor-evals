## Verdict

Exploitable. The user-supplied `reportName` parameter is concatenated directly into the ProcessStartInfo Arguments string without validation or parameterization, allowing an attacker to inject arbitrary commands via shell metacharacters. The command is executed via a batch file (`run-report.bat`), which is re-parsed by `cmd.exe` at the Windows system level even with `UseShellExecute = false`.

## Source

`[FromForm] string reportName` - unsanitized user input from HTTP POST form parameter.

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
            // Validate report name against allowlist to prevent command injection
            if (string.IsNullOrEmpty(reportName) || 
                !Regex.IsMatch(reportName, @"\A[a-zA-Z0-9_][a-zA-Z0-9_-]*\z"))
            {
                return BadRequest("Invalid report name");
            }

            string scriptPath = Path.Combine(_scriptsDir, "run-report.bat");

            var psi = new ProcessStartInfo
            {
                FileName = scriptPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                WorkingDirectory = _scriptsDir
            };

            // Use ArgumentList to pass arguments as separate elements instead of concatenating into a single string
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

The fix eliminates the vulnerability through two complementary defences. First, the dangerous string concatenation on line 27 is replaced with `ArgumentList`, which passes `-report` and the report name as separate argument elements instead of concatenating them into a single string. This prevents shell metacharacter injection at the C# level and isolates each argument from reinterpretation by the batch file parser. Second, strict input validation using a regular expression anchored with `\A` and `\z` (as specified in CWE-78 C# guidance) ensures that `reportName` contains only alphanumeric characters, underscores, and hyphens, with the first character required to be alphanumeric or underscore. This second layer prevents argument injection (CWE-88) by rejecting any value that could be misinterpreted as a command-line flag or contain special characters used in shell attacks. The fix preserves the existing contract: the function still captures and returns the process's standard output as plain text, maintains the same working directory, and returns an error response for invalid input.

## Behaviour changes

No behaviour changes to the success path. On invalid input (empty string, values not matching the allowlist, values starting with `-`), the endpoint now returns HTTP 400 Bad Request with the message "Invalid report name". The original code would have passed such values directly to the batch script, potentially causing unexpected script behaviour or command injection. This is a security-necessary change that prevents malicious input from reaching the process execution sink, and the explicit validation failure is more secure than silent script failure.
