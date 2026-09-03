## Verdict
Real issue confirmed. User-supplied `serverName` parameter is concatenated directly into the PowerShell command string without escaping, allowing arbitrary PowerShell commands to be injected via special characters like semicolons or backticks.

## Source
Line 16 in `PowerShellCommandConcat.cs` constructs the `-Command` argument using string concatenation:
```
Arguments = "-Command \"Test-Connection " + serverName + " -Count 4\"",
```

An attacker can inject PowerShell commands by supplying input like `localhost; Get-Content C:\sensitive.txt` or using backticks for command substitution.

## Fix
Escape backticks and double quotes in the `serverName` parameter before concatenating it into the PowerShell command string. Backticks are PowerShell's escape character, and quotes delimit strings; escaping both prevents breaking out of the quoted parameter.

```csharp
// Escape special characters in the server name to prevent PowerShell injection
string escapedServerName = serverName
    .Replace("`", "``")        // PowerShell escape character needs to be doubled
    .Replace("\"", "`\"");     // Escape double quotes with backtick for PowerShell

var psi = new ProcessStartInfo
{
    FileName = "powershell.exe",
    Arguments = "-Command \"Test-Connection `\"" + escapedServerName + "`\" -Count 4\"",
    UseShellExecute = false,
    RedirectStandardOutput = true
};

using var process = Process.Start(psi);
```

## Explanation
PowerShell interprets backticks and unescaped quotes within the `-Command` string. By escaping backticks as ``` `` ``` (doubled) and quotes as ``` `" ``` (backtick-prefixed), the input is treated as a literal hostname parameter rather than executable code. This prevents command injection even if the parameter contains semicolons, pipes, or other PowerShell operators—they will be treated as part of the hostname string passed to `Test-Connection`, not as command separators or syntax elements. The `-Count 4` parameter remains safely outside the escaped region and continues to be parsed as an option flag.
