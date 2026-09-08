## Verdict

exploitable

- cwe_id: CWE-78
- location: BatchScriptReentry.cs, line 34 (`Process.Start(psi)`)
- confidence: high

## Source

`reportName`, bound from the request body via `[FromForm] string reportName` on `GenerateReport`. This is attacker-controlled HTTP input with no validation applied before use.

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
        private static readonly Regex ReportNamePattern = new(@"\A[A-Za-z0-9_-]{1,64}\z", RegexOptions.Compiled);

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
                return BadRequest("reportName must contain only letters, digits, hyphens, and underscores (max 64 characters).");
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

The sink is a `.bat` target invoked through `Process.Start`. On Windows, a batch file has no argv array at the system-call level: `cmd.exe` re-parses the command line to run it even though `UseShellExecute` is `false`, so passing arguments via `ArgumentList` instead of a hand-built `Arguments` string reduces basic string-splitting bugs but does not by itself stop `cmd.exe` from re-interpreting metacharacters such as `&`, `|`, `^`, or `"` inside a value once it is substituted into the script's `%1`. The original code concatenated `reportName` directly into a single `Arguments` string with no validation at all, so a value like `report1 & calc.exe` reaches the batch invocation intact and is executed as a second command. The fix keeps the batch script invocation (running the bundled reporting tool is the endpoint's purpose, not incidental) and closes the gap the KB calls out for `.bat` targets by enforcing a strict allowlist format on `reportName` before it is used: only letters, digits, hyphens, and underscores, anchored with `\A`/`\z` rather than `^`/`$` so a trailing newline cannot slip through. Because none of the characters `cmd.exe` treats specially can pass this format check, the value can no longer be used to inject a second command regardless of how the batch file re-parses its arguments. `ArgumentList` is also adopted in place of manual string concatenation as defense in depth for correct argument separation, though the allowlist is what actually closes the injection.

## Behaviour changes

- Added format validation on `reportName`: requests where the name does not match `[A-Za-z0-9_-]{1,64}` now return `400 Bad Request` instead of being passed to the batch script. This is required because neither `UseShellExecute = false` nor `ArgumentList` prevents `cmd.exe`'s re-parsing of a `.bat` target's arguments, so rejecting shell-metacharacter-bearing input is the control that closes the injection. Legitimate report identifiers (alphanumeric names, optionally with `-`/`_`) are unaffected.
- Replaced the single concatenated `Arguments` string with two `ArgumentList` entries (`-report`, `reportName`). This does not change what is passed to the script for a value that already passes the new allowlist - it removes the string-concatenation step itself as a second layer.
- No change to `UseShellExecute`, `RedirectStandardOutput`, `WorkingDirectory`, the script path, or how output is read and returned - the sink's return value, discarded stderr/exit-code handling, and failure behaviour (`process!` null-forgiving dereference) are all preserved from the original.

verification: Copied the fixed file into a scratch ASP.NET Core project (`Microsoft.NET.Sdk.Web`, target `net8.0`) alongside a minimal `Program.cs` and ran `dotnet build`. Build succeeded with 0 warnings and 0 errors, confirming the code compiles and every API used (`ProcessStartInfo.ArgumentList`, `Regex` with `RegexOptions.Compiled`, `ControllerBase.BadRequest`) resolves correctly.

assumptions: The allowed report-name charset (`[A-Za-z0-9_-]`, max 64 chars) is inferred from typical report-identifier conventions since the application's actual set of valid report names is not visible in the provided file; the application should tighten this to an enumerated allowlist of known report names if one exists.
