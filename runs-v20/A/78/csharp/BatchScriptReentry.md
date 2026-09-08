## Verdict

Confirmed. `reportName` is taken directly from the HTTP request body and concatenated into the `Arguments` string passed to `Process.Start`, which launches a `.bat` file. On Windows, starting a batch file - even with `UseShellExecute = false` - is implemented by the OS through an implicit `cmd.exe` invocation, so the batch file's arguments are subject to `cmd.exe` metacharacter interpretation (`&`, `|`, `^`, `%`, `<`, `>`, quotes, etc.). A caller can supply a value such as `report1 & whoami` (or a `%VAR%` expansion, or a second `&`-chained command) and have it executed as an additional command, or reenter the batch pipeline with attacker-chosen arguments.

## Source

`reportName`, bound from the request body via `[FromForm] string reportName` in `ReportsController.GenerateReport`. It is fully attacker-controlled and reaches the sink unvalidated and unescaped.

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
        // Report names are internal identifiers for bundled reports, not free text -
        // restrict to the characters those identifiers actually use.
        private static readonly Regex ReportNamePattern = new Regex(@"^[A-Za-z0-9_-]+$", RegexOptions.Compiled);

        private readonly string _scriptsDir;

        public ReportsController(IWebHostEnvironment env)
        {
            _scriptsDir = Path.Combine(env.ContentRootPath, "Scripts");
        }

        // Runs the bundled reporting batch script against a caller-supplied report name.
        [HttpPost("generate")]
        public IActionResult GenerateReport([FromForm] string reportName)
        {
            if (string.IsNullOrEmpty(reportName) || !ReportNamePattern.IsMatch(reportName))
            {
                return BadRequest("reportName must contain only letters, digits, hyphens, and underscores.");
            }

            string scriptPath = Path.Combine(_scriptsDir, "run-report.bat");

            var psi = new ProcessStartInfo
            {
                FileName = scriptPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                WorkingDirectory = _scriptsDir
            };
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

Two changes close the injection, and each covers a gap the other does not:

- **Allowlist validation on `reportName`.** Report names are an application-defined identifier space (they select a bundled report, not arbitrary text), so a strict allowlist is the right primary control here, not a bolted-on afterthought: `^[A-Za-z0-9_-]+$` rejects every `cmd.exe` metacharacter (`&`, `|`, `^`, `%`, `<`, `>`, quotes, spaces) as well as path-separator characters, so a value can no longer chain a second command, expand an environment variable, or redirect output. Invalid input now gets a `400 Bad Request` instead of reaching the process launch.
- **`ArgumentList` instead of a concatenated `Arguments` string.** Even with a validated value, building `Arguments` via string concatenation is fragile - .NET has to re-tokenize that single string using Win32 quoting rules, and a value containing a space or an unbalanced quote can still be split into extra positional arguments or flags. `ProcessStartInfo.ArgumentList` passes `-report` and `reportName` as two discrete elements, so each is delivered to the child process as a single argument regardless of its content, removing the string-splitting ambiguity entirely.

The allowlist is the control that actually neutralizes the `cmd.exe` metacharacter risk introduced by launching a `.bat` file; `ArgumentList` is a secondary hardening step that prevents argument-splitting bugs but does not by itself stop metacharacters from being interpreted by the batch script's implicit shell, since `.bat` launch still goes through `cmd.exe` regardless of how the argument was assembled. Together, the validated character set and the discrete argument list mean the value handed to `run-report.bat` can never contain a byte capable of terminating or extending the command line.
