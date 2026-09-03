## Verdict

Exploitable

## Source

The `serverName` parameter sourced from `[FromQuery] string serverName` on line 11, passed to an HTTP GET endpoint without validation.

## Fix

**Vulnerable Code:**
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
process.WaitForExit();
```

**Fixed Code:**
```csharp
// Validate the hostname using a strict allowlist pattern
if (string.IsNullOrWhiteSpace(serverName) || !Regex.IsMatch(serverName, @"\A[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\z"))
{
    return BadRequest("Invalid server name");
}

// Use Ping class instead of executing PowerShell
var ping = new System.Net.NetworkInformation.Ping();
var results = new List<string>();

try
{
    for (int i = 0; i < 4; i++)
    {
        var reply = ping.Send(serverName, 5000);
        if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
        {
            results.Add($"Reply from {reply.Address}: bytes={reply.Buffer.Length} time={reply.RoundtripTime}ms TTL={reply.Options.Ttl}");
        }
        else
        {
            results.Add($"Request timed out or host unreachable: {reply.Status}");
        }
    }
    string output = string.Join(Environment.NewLine, results);
    return Content(output, "text/plain");
}
catch (System.Net.NetworkInformation.PingException ex)
{
    return BadRequest($"Ping failed: {ex.Message}");
}
```

## Explanation

The vulnerability was eliminated by replacing the PowerShell command execution entirely with .NET's native `System.Net.NetworkInformation.Ping` class. The original code concatenated untrusted `serverName` directly into a PowerShell `-Command` argument, which interprets the entire string as script code, allowing arbitrary command execution. The fixed code removes the Process.Start() call entirely and uses the framework's built-in network diagnostics API. Input validation using a strict hostname regex pattern (anchored with `\A` and `\z` per C# guidance) ensures the value conforms to valid hostname syntax before being passed to Ping. This approach eliminates the injection surface completely—there is no command execution, no string parsing of the hostname, and no shell interpretation of any kind. The output format mimics the standard Windows ping response to maintain API compatibility.

## Behaviour changes

The fix replaces ProcessStartInfo-based PowerShell execution with managed .NET Ping API calls:

- **Return type unchanged**: Both return string content via `Content(output, "text/plain")`, preserving the original response format.
- **Output format**: Fixed code mimics standard ping output (IP addresses, response times, TTL values) from the PingReply object to maintain functional equivalence with the original shell output.
- **Error handling**: Replaced process execution exceptions with structured error responses (`BadRequest()` for invalid input or PingException for network errors) instead of allowing exceptions to propagate or capturing stderr.
- **Hostname validation**: Added strict allowlist validation on line 1 to reject malformed hostnames before processing. The original code had no validation and would pass any string to PowerShell.
- **Input source confirmation**: Validation operates on the exact value that reaches the sink (the hostname passed to Ping), not an earlier entry point, confirming the check is effective.
- **Timeout handling**: Ping.Send() includes explicit 5000ms timeout per iteration. Original ProcessStartInfo did not configure timeouts, so the process could hang indefinitely.
- **Loop iterations**: Loop performs exactly 4 sends to match the `-Count 4` behavior of the original PowerShell command.
- **Implicit parameters preserved**: No null parameters or omitted defaults introduced; all API contracts remain satisfied.
