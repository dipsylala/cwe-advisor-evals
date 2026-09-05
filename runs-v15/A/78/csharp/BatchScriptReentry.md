## Verdict
Confirmed. The `reportName` parameter is user-supplied and concatenated directly into process arguments without validation. When passed to a batch script via `Process.Start()`, batch metacharacters (e.g., `&`, `|`, `^`, `>`, `<`) are interpreted by the batch interpreter, allowing command injection despite `UseShellExecute = false`.

## Source
Line 20: `reportName` parameter from HTTP request (user-controlled).

Line 27: Unsafe concatenation into command-line arguments: `Arguments = "-report " + reportName`.

Line 34: Sink is `Process.Start(psi)`, which passes the concatenated string to the batch interpreter.

## Fix
Replace the unsafe concatenation with an allowlist validation. Accept only alphanumeric characters, underscores, and hyphens in the report name:

```csharp
if (!Regex.IsMatch(reportName, @"^[a-zA-Z0-9_-]+$"))
{
    return BadRequest("Invalid report name");
}

var psi = new ProcessStartInfo
{
    FileName = scriptPath,
    Arguments = "-report " + reportName,
    UseShellExecute = false,
    RedirectStandardOutput = true,
    WorkingDirectory = _scriptsDir
};
```

Add `using System.Text.RegularExpressions;` at the top of the file.

Alternatively, if report names require a broader character set, use `ProcessStartInfo.ArgumentList` (available in .NET 6+) to pass arguments as separate items, bypassing shell interpretation:

```csharp
var psi = new ProcessStartInfo
{
    FileName = scriptPath,
    UseShellExecute = false,
    RedirectStandardOutput = true,
    WorkingDirectory = _scriptsDir
};
psi.ArgumentList.Add("-report");
psi.ArgumentList.Add(reportName);
```

## Explanation
Batch files interpret special characters even when called via `Process.Start()` with `UseShellExecute = false`. An attacker who controls `reportName` can inject batch commands by including metacharacters such as `&` (command separator), `|` (pipe), `^` (escape), `>` or `<` (redirection), or `%` sequences.

The allowlist approach restricts report names to safe characters that have no special meaning to the batch interpreter. The `ArgumentList` alternative (if available) passes arguments as distinct tokens to the batch interpreter, preventing them from being re-parsed as shell syntax.

Both defenses ensure that user input cannot alter the command structure or inject additional commands.
