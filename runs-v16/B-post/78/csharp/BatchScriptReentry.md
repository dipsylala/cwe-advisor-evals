## Verdict

Real, confirmed OS Command Injection vulnerability. The `reportName` parameter is directly concatenated into command arguments without validation, allowing command injection despite `UseShellExecute = false` due to batch file re-parsing at the system-call level.

## Source

The data flow originates from an HTTP POST endpoint parameter:
- **Source**: `[FromForm] string reportName` (line 19) — untrusted user input
- **Intermediate**: String concatenation on line 27: `Arguments = "-report " + reportName`
- **Sink**: `Process.Start(psi)` on line 34 — executes the process with tainted arguments

An attacker can pass `reportName = "test.csv & del /s /q c:\*"` (or similar payloads) which will be parsed and executed as additional commands when `cmd.exe` interprets the batch file arguments at runtime.

## Fix

```csharp
using System.Text.RegularExpressions;
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

        [HttpPost("generate")]
        public IActionResult GenerateReport([FromForm] string reportName)
        {
            // Validate reportName against an allowlist — only alphanumeric, hyphen, underscore allowed
            if (string.IsNullOrEmpty(reportName) || !Regex.IsMatch(reportName, @"\A[a-zA-Z0-9_-]+\z"))
            {
                return BadRequest("Invalid report name");
            }

            string scriptPath = Path.Combine(_scriptsDir, "run-report.bat");

            var psi = new ProcessStartInfo
            {
                FileName = scriptPath,
                ArgumentList = { "-report", reportName },  // Separate arguments prevent shell metacharacter injection
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

The vulnerability arises because `reportName` was concatenated directly into the `Arguments` string, allowing shell metacharacters and command separators to inject arbitrary commands. Although `UseShellExecute = false` is set, it only controls the graphical shell on .NET Framework; the target is a Windows batch file (`.bat`), and at the system-call level, Windows has no argv array. Instead, `cmd.exe` re-parses the command line for batch files, meaning command separators (`&`, `|`, `&&`, `||`) and redirection (`>`, `<`) in the arguments are still interpreted as shell syntax.

The fix applies defense-in-depth:

1. **Input validation (primary defence)**: An allowlist regex `\A[a-zA-Z0-9_-]+\z` ensures the report name contains only safe characters. Whitespace, quotes, ampersands, pipes, parentheses, and other shell metacharacters are rejected before reaching the sink. The anchors `\A` and `\z` prevent matches to inputs with trailing newlines.

2. **Argument separation (secondary defence)**: `ArgumentList` (available in .NET 5+, .NET Core 2.1+, and .NET Standard 2.1+) passes each argument as a separate element rather than a concatenated string. This prevents shell metacharacter injection in most cases. However, for batch file targets, this protection is incomplete because `cmd.exe` still re-parses the entire command line; the allowlist validation is the load-bearing defence here.

The fix preserves the original contract: it still returns the batch script's output via `StandardOutput` and maintains the same error handling and return type.

## Behaviour changes

- **New import**: `System.Text.RegularExpressions` for regex validation
- **New validation**: Invalid report names (containing special characters, whitespace, etc.) are rejected with HTTP 400 Bad Request instead of being passed to the process
- **Argument construction change**: Switched from string concatenation to `ArgumentList`, separating `-report` and `reportName` into distinct argument elements
- **Valid payloads affected**: Report names must now match `[a-zA-Z0-9_-]+`. Report names with spaces, quotes, or other characters will be rejected. If legitimate report names contain such characters, the allowlist should be widened accordingly (e.g., to include dots: `[a-zA-Z0-9_\-.]+`).
