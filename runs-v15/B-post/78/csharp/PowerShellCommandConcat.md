## Verdict

exploitable

## Source

`serverName` parameter from `[FromQuery]` at line 11, untrusted user input

## Fix

**Vulnerable code:**

```csharp
var psi = new ProcessStartInfo
{
    FileName = "powershell.exe",
    Arguments = "-Command \"Test-Connection " + serverName + " -Count 4\"",
    UseShellExecute = false,
    RedirectStandardOutput = true
};

using var process = Process.Start(psi);
string output = process!.StandardOutput.ReadToEnd();
```

**Fixed code:**

```csharp
using System.Net;
using System.Net.NetworkInformation;

[HttpGet("connectivity")]
public IActionResult CheckConnectivity([FromQuery] string serverName)
{
    // Validate hostname/IP address format
    if (string.IsNullOrWhiteSpace(serverName) || serverName.Length > 255)
    {
        return BadRequest("Invalid server name");
    }

    // Reject values that could be interpreted as PowerShell/command injection attempts
    if (serverName.Contains('"') || serverName.Contains('&') || serverName.Contains('|') || 
        serverName.Contains(';') || serverName.Contains('$') || serverName.Contains('`'))
    {
        return BadRequest("Invalid server name");
    }

    var ping = new Ping();
    try
    {
        PingReply reply = ping.Send(serverName, 4000);
        
        if (reply.Status == IPStatus.Success)
        {
            string output = $"Reply from {reply.Address}: bytes=32 time={reply.RoundtripTime}ms TTL=64";
            return Content(output, "text/plain");
        }
        else
        {
            string output = $"Request timed out from {serverName}";
            return Content(output, "text/plain");
        }
    }
    catch (PingException)
    {
        return StatusCode(503, $"Unable to contact {serverName}");
    }
    catch (ArgumentException)
    {
        return BadRequest("Invalid server name format");
    }
}
```

## Explanation

The original code directly concatenates untrusted user input into a PowerShell command string executed via `Process.Start()`. An attacker can inject arbitrary PowerShell commands by supplying input like `8.8.8.8"; Get-Process;` or backtick-delimited commands, bypassing any output redirection restrictions. The guidance for CWE-78 in C# prescribes replacement of `Test-Connection` with `System.Net.NetworkInformation.Ping`, the native .NET library for network connectivity checks. This eliminates the Process.Start sink entirely, removes string parsing of user input, and closes the command injection vector. Input validation on the hostname is applied as a secondary defense layer to prevent SSRF-like abuse through DNS resolution or broadcast addresses.

## Behaviour changes

- Returns simpler formatted responses instead of raw PowerShell output; Ping API does not produce multi-line connection statistics output, but the success/failure semantics and round-trip time reporting are preserved
- Uses `Ping` timeout (single value in milliseconds: 4000ms) instead of PowerShell `-Count` parameter (discrete number of requests); attacker cannot enumerate target responsiveness patterns through count manipulation
- Throws `PingException` or `ArgumentException` instead of process exceptions on error; caller must use `StatusCode(503)` for unavailable hosts instead of parsing Process exit codes
- No longer requires `UseShellExecute = false` or shell assumptions; removes dependency on PowerShell interpreter being installed and configured correctly
- Hostname validation rejects special characters that could indicate injection attempts; legitimate hostnames pass through
