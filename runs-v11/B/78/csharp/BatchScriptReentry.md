## Verdict

CONFIRMED - CWE-78 OS Command Injection via unvalidated user input concatenated into process arguments targeting a batch file.

## Source

User-controlled `reportName` parameter from HTTP POST form (line 20) flows directly into the process Arguments string without validation or parameterization (line 27). The batch file target causes Windows to re-parse the command line through cmd.exe, enabling metacharacter injection.

## Fix

**Recommended approach: Replace batch file invocation**

Determine what executable the batch file wraps and invoke it directly instead, eliminating the command-shell layer:

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
        // Allowlist of valid report names - adjust to your actual report names
        private static readonly Regex ValidReportName = new(@"\A[a-zA-Z0-9_-]+\z");

        public ReportsController(IWebHostEnvironment env)
        {
            _scriptsDir = Path.Combine(env.ContentRootPath, "Scripts");
        }

        [HttpPost("generate")]
        public IActionResult GenerateReport([FromForm] string reportName)
        {
            // Validate report name against allowlist
            if (string.IsNullOrEmpty(reportName) || !ValidReportName.IsMatch(reportName))
            {
                return BadRequest("Invalid report name");
            }

            // PREFERRED: Invoke the executable that run-report.bat wraps, not the batch file itself
            // Replace "report-generator.exe" with the actual executable path
            string executablePath = Path.Combine(_scriptsDir, "report-generator.exe");

            var psi = new ProcessStartInfo
            {
                FileName = executablePath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                WorkingDirectory = _scriptsDir
            };

            // Use ArgumentList (available in .NET Core 2.1+) to pass arguments safely as an array
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

**Fallback approach: If the batch file cannot be replaced**

If the batch file must be retained, use `ArgumentList` with strict input validation:

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
        private static readonly Regex ValidReportName = new(@"\A[a-zA-Z0-9_-]+\z");

        public ReportsController(IWebHostEnvironment env)
        {
            _scriptsDir = Path.Combine(env.ContentRootPath, "Scripts");
        }

        [HttpPost("generate")]
        public IActionResult GenerateReport([FromForm] string reportName)
        {
            if (string.IsNullOrEmpty(reportName) || !ValidReportName.IsMatch(reportName))
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

            // Use ArgumentList to pass arguments as an array (requires .NET Core 2.1+)
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

The vulnerability occurs because user input (`reportName`) is directly concatenated into the process Arguments string without validation. When the target is a Windows batch file (`.bat`), the operating system has no argv array at the system-call level—cmd.exe re-parses the entire command line, allowing an attacker to inject shell metacharacters. For example, `report.csv & taskkill /F /IM explorer.exe` would delete the system explorer process.

The recommended fix eliminates the batch file layer entirely by invoking the underlying executable directly. If the batch file cannot be removed, the fix uses `ArgumentList` (available in .NET Core 2.1+) to pass arguments as separate array elements rather than concatenating them into a single string, combined with strict input validation using an allowlist pattern. The allowlist pattern `\A[a-zA-Z0-9_-]+\z` anchors with `\A` and `\z` (not `^` and `$`, which in .NET accept trailing newlines) to ensure only safe characters pass through.

Note: `ArgumentList` does not fully protect batch files from re-parsing since Windows still invokes cmd.exe for `.bat` targets—the primary fix is to replace the batch file with direct executable invocation where possible.

## Behaviour changes

- **Arguments passing**: Changed from string concatenation to an argument array via `ArgumentList`, ensuring shell metacharacters in user input are not interpreted as commands
- **Input validation**: Added strict allowlist validation (`[a-zA-Z0-9_-]+`) to reject invalid report names before they reach the process
- **Process target** (recommended approach): Changed from batch file invocation to direct executable invocation, eliminating the cmd.exe re-parsing layer entirely
- **Error handling**: Added validation that returns HTTP 400 (Bad Request) for invalid input rather than attempting to execute
- **Return value**: Preserved—still reads and returns process stdout as plain text
- **Standard error**: Still discarded (same as original)
