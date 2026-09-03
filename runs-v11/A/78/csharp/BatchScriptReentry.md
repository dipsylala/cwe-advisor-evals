## Verdict
Confirmed CWE-78 OS Command Injection.

## Source
Line 27 concatenates an unvalidated user-supplied `reportName` directly into the process arguments:
```csharp
Arguments = "-report " + reportName,
```

The `reportName` parameter originates from user input via `[FromForm] string reportName` and is not validated before being passed to `Process.Start()`. An attacker can inject special characters or additional arguments to alter the batch script's behavior.

## Fix
Validate `reportName` using an allowlist to accept only safe characters (alphanumeric, hyphens, underscores, and dots):

```csharp
[HttpPost("generate")]
public IActionResult GenerateReport([FromForm] string reportName)
{
    // Validate reportName to only contain safe characters
    if (string.IsNullOrEmpty(reportName) || !System.Text.RegularExpressions.Regex.IsMatch(reportName, @"^[a-zA-Z0-9._-]+$"))
    {
        return BadRequest("Invalid report name. Only alphanumeric characters, dots, hyphens, and underscores are allowed.");
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
```

Alternatively, extract the validation into a helper method for reuse:

```csharp
private bool IsValidReportName(string reportName)
{
    return !string.IsNullOrEmpty(reportName) && System.Text.RegularExpressions.Regex.IsMatch(reportName, @"^[a-zA-Z0-9._-]+$");
}

[HttpPost("generate")]
public IActionResult GenerateReport([FromForm] string reportName)
{
    if (!IsValidReportName(reportName))
    {
        return BadRequest("Invalid report name.");
    }

    // ... rest of method unchanged
}
```

## Explanation
The vulnerability exists because `reportName` is user-controlled and concatenated directly into the process arguments without any validation. Although `UseShellExecute = false` prevents shell interpretation at the Windows process level, the batch file itself may process arguments in an unsafe way (e.g., echoing them into commands, using them in conditionals, or passing them to other tools that interpret special characters). An attacker could include characters like `&`, `|`, `>`, or `%` to inject additional commands or alter the intended behavior.

The fix enforces an allowlist validation that only permits report names containing letters, digits, dots, hyphens, and underscores—characters safe for use as batch script arguments and filenames. Any request with invalid characters is rejected with a 400 Bad Request response. This approach prevents the injection while maintaining usability for legitimate report names.
