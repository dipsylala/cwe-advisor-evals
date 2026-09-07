## Verdict

The code is vulnerable to OS command injection through string concatenation of an untrusted query parameter into a PowerShell command.

## Source

File: PowerShellCommandConcat.cs, line 16

The `serverName` parameter from the HTTP query string is directly concatenated into the PowerShell command:
```csharp
Arguments = "-Command \"Test-Connection " + serverName + " -Count 4\"",
```

An attacker can inject PowerShell metacharacters and commands, e.g., `serverName = "8.8.8.8; Remove-Item -Path C:\critical -Force"`.

## Fix

### File: PowerShellCommandConcat.cs

```csharp
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("api/admin/[controller]")]
    public class ServerDiagnosticsController : ControllerBase
    {
        [HttpGet("connectivity")]
        public IActionResult CheckConnectivity([FromQuery] string serverName)
        {
            // Validate input
            if (string.IsNullOrWhiteSpace(serverName))
            {
                return BadRequest("Server name is required");
            }

            // Escape single quotes for PowerShell string value
            string escapedServerName = serverName.Replace("'", "''");

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                // Pass serverName as a parameter via -ArgumentList, not via string concatenation
                Arguments = $"-Command \"Test-Connection -ComputerName $($args[0]) -Count 4\" -ArgumentList '{escapedServerName}'",
                UseShellExecute = false,
                RedirectStandardOutput = true
            };

            // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
            using var process = Process.Start(psi);

            string output = process!.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return Content(output, "text/plain");
        }
    }
}
```

## Explanation

The fix uses PowerShell's `-ArgumentList` parameter to pass `serverName` separately from the command, preventing injection:

1. **Input validation**: Check that `serverName` is not empty before use.
2. **Proper escaping**: Escape single quotes in the parameter value by doubling them (`'` → `''`), which is PowerShell's escape syntax within single-quoted strings.
3. **Parameterized passing**: Use `-ArgumentList` to pass the server name as a distinct parameter argument, accessed within the command via `$($args[0])`, rather than concatenating it directly into the command string.
4. **Separation of code and data**: The command structure is now fixed in code, and user input flows only through parameter binding, preventing PowerShell metacharacters from being interpreted as command syntax.

This ensures that any characters in `serverName`—including semicolons, pipes, parentheses, or other PowerShell special characters—are treated as literal string values, not as command syntax.
