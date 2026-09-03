## Verdict

**CONFIRMED** - OS Command Injection via string concatenation into process arguments. User-supplied `reportName` is concatenated directly into the Arguments string without validation (line 27). Even with `UseShellExecute = false`, targeting a `.bat` file causes `cmd.exe` to re-parse the command line, allowing injection.

## Source

```csharp
[HttpPost("generate")]
public IActionResult GenerateReport([FromForm] string reportName)
{
    string scriptPath = Path.Combine(_scriptsDir, "run-report.bat");

    var psi = new ProcessStartInfo
    {
        FileName = scriptPath,
        Arguments = "-report " + reportName,  // ← Tainted concatenation
        UseShellExecute = false,
        RedirectStandardOutput = true,
        WorkingDirectory = _scriptsDir
    };

    using var process = Process.Start(psi);  // ← Sink (line 34)
    // ...
}
```

## Fix

Replace the vulnerable concatenation with an allowlist-validated approach using `ArgumentList`:

```csharp
[HttpPost("generate")]
public IActionResult GenerateReport([FromForm] string reportName)
{
    // Strict allowlist: report names must be alphanumeric, hyphen, or underscore only
    if (!System.Text.RegularExpressions.Regex.IsMatch(reportName, @"\A[a-zA-Z0-9_-]+\z"))
    {
        return BadRequest("Invalid report name. Use only alphanumeric characters, hyphens, and underscores.");
    }

    string scriptPath = Path.Combine(_scriptsDir, "run-report.bat");

    var psi = new ProcessStartInfo
    {
        FileName = scriptPath,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        WorkingDirectory = _scriptsDir
    };
    
    // Use ArgumentList instead of Arguments string concatenation
    // Note: ArgumentList requires .NET Core 2.1+ (not available in .NET Framework)
    psi.ArgumentList.Add("-report");
    psi.ArgumentList.Add(reportName);

    using var process = Process.Start(psi);
    
    string output = process!.StandardOutput.ReadToEnd();
    process.WaitForExit();

    return Content(output, "text/plain");
}
```

## Explanation

The fix closes the injection point through two layers of defence:

1. **Input Validation (Secondary Defence)**: A strict allowlist ensures `reportName` contains only safe characters (alphanumerics, hyphens, underscores). This rejects payloads containing spaces, semicolons, pipes, and other shell metacharacters before they reach the process.

2. **Parameterized Arguments (Primary Defence)**: `ArgumentList` passes each argument as a discrete parameter instead of concatenating into a single string. On .NET Core 2.1+, this prevents the arguments from being re-parsed by the shell.

**Important Caveat**: While `ArgumentList` prevents shell metacharacter injection, batch files are still inherently risky. Windows batch processing causes `cmd.exe` to re-parse the command line even when arguments are passed separately. The most secure long-term fix is to identify the underlying executable the batch file wraps and call it directly, bypassing the batch script re-parsing entirely. If that is not possible, maintain the allowlist validation as a secondary defence layer to constrain what can be injected.

The fix preserves the sink's contract: it still returns process output to the caller as before.

## Behaviour changes

- **API Change**: Code now requires `.NET Core 2.1`, `.NET Standard 2.1`, or `.NET 5+`. `ArgumentList` does not exist in any `.NET Framework` version; on Framework, fall back to manually quoting `Arguments` and add strict validation.
- **Input Rejection**: Report names not matching `[a-zA-Z0-9_-]+` now return HTTP 400 Bad Request instead of being passed to the batch script. This prevents legitimate reports with special characters in their names. If batch scripts require different naming rules, adjust the regex pattern to the actual allowlist.
- **Error Handling**: Input validation failures now return an error response before any process is spawned, reducing resource consumption on malformed requests.
