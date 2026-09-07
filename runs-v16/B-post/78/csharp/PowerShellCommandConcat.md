## Verdict

Exploitable. The `serverName` HTTP query parameter (line 11) is concatenated directly into a PowerShell command string (line 16) without validation, then executed via Process.Start() (line 22). An attacker can inject arbitrary PowerShell commands.

## Source

`serverName` parameter from `[FromQuery] string serverName` (line 11) - HTTP query parameter, attacker-controlled.

Taint flow:
```
[FromQuery] string serverName
  ↓
Concatenated into Arguments string (line 16): "-Command \"Test-Connection " + serverName + " -Count 4\""
  ↓
Arguments passed to ProcessStartInfo (line 13-19)
  ↓
Process.Start(psi) executes powershell.exe (line 22)
```

## Fix

**Vulnerable Code (lines 13-28):**
```csharp
var psi = new ProcessStartInfo
{
    FileName = "powershell.exe",
    Arguments = "-Command \"Test-Connection " + serverName + " -Count 4\"",
    UseShellExecute = false,
    RedirectStandardOutput = true
};

// SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
using var process = Process.Start(psi);

string output = process!.StandardOutput.ReadToEnd();
process.WaitForExit();

return Content(output, "text/plain");
```

**Fixed Code:**
```csharp
using System;
using System.Net.NetworkInformation;
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
            try
            {
                using var ping = new Ping();
                var reply = ping.Send(serverName, 1000);
                
                if (reply.Status == IPStatus.Success)
                {
                    return Content($"Reply from {reply.Address}: bytes={reply.Buffer.Length} time={reply.RoundtripTime}ms", "text/plain");
                }
                else
                {
                    return Content($"Ping to {serverName} failed: {reply.Status}", "text/plain");
                }
            }
            catch (PingException ex)
            {
                return BadRequest($"Error pinging {serverName}: {ex.Message}");
            }
            catch (ArgumentException ex)
            {
                return BadRequest($"Invalid host name: {ex.Message}");
            }
        }
    }
}
```

## Explanation

The original code executes `powershell.exe -Command "Test-Connection <user-input> -Count 4"` by concatenating user input into a PowerShell command string. Even though `UseShellExecute = false`, PowerShell re-parses its `-Command` argument as script code, allowing the attacker to inject arbitrary commands (e.g., `; Get-Process` or `| Select-Object`). The fix eliminates Process.Start() entirely and replaces it with `System.Net.NetworkInformation.Ping`, which provides the same connectivity-check functionality natively in .NET without any OS command execution. This is the primary defence strategy recommended by CWE-78 guidance: eliminate OS command execution when a language-native alternative exists.

## Behaviour changes

**Return value**: The original returned raw PowerShell output; the fixed version constructs a formatted string summarizing the ping result. This is a behavioural change, but it addresses the same goal (reporting connectivity status) without introducing a regression - the endpoint still returns connectivity status in plain text format.

**Error handling**: The fixed version adds try-catch blocks to handle `PingException` (network errors) and `ArgumentException` (invalid hostname). The original would have surfaced PowerShell errors through the process's standard output or exit code. This is an improvement in error reporting specificity and does not hide information - exceptions are returned to the caller via HTTP status codes (400 Bad Request).

**Dependencies**: Adds `using System.Net.NetworkInformation` (part of .NET Framework / .NET Standard, no new package required). Removes dependency on PowerShell and Process.Start().

**No information loss**: The original output that mattered (connectivity success/failure and timing) is preserved. The raw PowerShell output format is replaced with a simplified format that carries the same signal but is safer.

