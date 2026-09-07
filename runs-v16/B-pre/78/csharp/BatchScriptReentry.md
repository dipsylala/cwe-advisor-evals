## Verdict

Exploitable. The `reportName` parameter from the form is concatenated directly into the ProcessStartInfo.Arguments string without validation or parameterization, allowing an attacker to inject batch script commands.

## Source

**Data flow trace:**
- Source: `reportName` parameter from `[FromForm]` attribute (line 20) - attacker-controlled input from HTTP form data
- Intermediate: Concatenated into Arguments string at line 27: `Arguments = "-report " + reportName`
- Sink: `Process.Start(psi)` at line 34 - executes the batch script with injected payload

**Example exploitation:**
An attacker posts `reportName=test & del /s /q C:\` which becomes `Arguments = "-report test & del /s /q C:\"`. When the batch file executes, cmd.exe parses this as two commands: one for the reporting tool and one to delete files.

## Fix

**Vulnerable code:**
```csharp
var psi = new ProcessStartInfo
{
    FileName = scriptPath,
    Arguments = "-report " + reportName,  // String concatenation allows injection
    UseShellExecute = false,
    RedirectStandardOutput = true,
    WorkingDirectory = _scriptsDir
};

using var process = Process.Start(psi);
```

**Fixed code:**
```csharp
// Validate report name: alphanumeric characters, underscores, and hyphens only
if (string.IsNullOrEmpty(reportName) || !System.Text.RegularExpressions.Regex.IsMatch(reportName, @"\A[a-zA-Z0-9_-]+\z"))
{
    return BadRequest("Invalid report name");
}

var psi = new ProcessStartInfo
{
    FileName = scriptPath,
    ArgumentList = { "-report", reportName },  // Separate argument array instead of string concatenation
    UseShellExecute = false,
    RedirectStandardOutput = true,
    WorkingDirectory = _scriptsDir
};

using var process = Process.Start(psi);
```

## Explanation

The fix eliminates the command injection by applying two layers of defence. First, strict input validation using a regex anchored with `\A` and `\z` (not `^` and `$`, which match before trailing newlines in .NET) restricts `reportName` to alphanumeric characters, underscores, and hyphens, preventing injection of batch metacharacters like `&`, `|`, `;`, `(`, and `)`. Second, replacing string concatenation with `ArgumentList` ensures the report name is passed as a separate, discrete argument rather than being concatenated into a command string that cmd.exe can reparse. While batch files on Windows do have the caveat that cmd.exe re-parses the argument line (per CWE-78 guidance on `.bat` targets), the combination of ArgumentList and strict validation prevents an attacker from injecting command separators or other shell syntax.

## Behaviour changes

The fix introduces input validation that rejects report names containing characters outside `[a-zA-Z0-9_-]`. Legitimate report names using only those characters are unaffected. Any request with a name containing special characters (e.g., spaces, punctuation, or batch syntax) will now return HTTP 400 (BadRequest) instead of attempting execution. This is intentional and eliminates the attack surface; no other changes to the return value, error handling, or output handling occur.
