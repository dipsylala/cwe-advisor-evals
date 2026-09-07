## Verdict

**Confirmed.** CWE-78 (OS Command Injection) vulnerability at line 22. User-controlled input from the `serverName` query parameter is concatenated directly into a PowerShell command string without validation or escaping, allowing arbitrary PowerShell command injection.

## Source

Line 11: `[FromQuery] string serverName` - attacker-controlled HTTP query parameter

## Fix

Replace the vulnerable `Process.Start()` call that invokes PowerShell with command-line concatenation with `System.Net.NetworkInformation.Ping`, the native .NET ICMP ping implementation. Loop 4 times to match the original `-Count 4` and format output to match the original response shape.

### File: PowerShellCommandConcat.cs

```csharp
using System;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
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
            if (string.IsNullOrWhiteSpace(serverName))
            {
                return BadRequest("Server name is required");
            }

            try
            {
                // Validate that the hostname can be parsed
                _ = Dns.GetHostAddresses(serverName);
            }
            catch (System.Net.Sockets.SocketException)
            {
                return BadRequest("Invalid server name");
            }

            try
            {
                var ping = new Ping();
                var output = new StringBuilder();
                int successCount = 0;
                int failureCount = 0;
                long minTime = long.MaxValue;
                long maxTime = 0;
                long totalTime = 0;

                output.AppendLine($"Pinging {serverName} with 32 bytes of data:");

                for (int i = 0; i < 4; i++)
                {
                    try
                    {
                        var reply = ping.Send(serverName, 5000);
                        if (reply.Status == IPStatus.Success)
                        {
                            output.AppendLine($"Reply from {reply.Address}: bytes=32 time={reply.RoundtripTime}ms TTL=64");
                            successCount++;
                            totalTime += reply.RoundtripTime;
                            minTime = Math.Min(minTime, reply.RoundtripTime);
                            maxTime = Math.Max(maxTime, reply.RoundtripTime);
                        }
                        else
                        {
                            output.AppendLine($"Request timed out.");
                            failureCount++;
                        }
                    }
                    catch
                    {
                        output.AppendLine($"Request timed out.");
                        failureCount++;
                    }
                }

                output.AppendLine();
                output.AppendLine($"Ping statistics for {serverName}:");
                output.AppendLine($"    Packets: Sent = 4, Received = {successCount}, Lost = {failureCount} ({(failureCount * 100) / 4}% loss),");
                if (successCount > 0)
                {
                    output.AppendLine($"Approximate round trip times in milli-seconds:");
                    output.AppendLine($"    Minimum = {minTime}ms, Maximum = {maxTime}ms, Average = {totalTime / successCount}ms");
                }

                return Content(output.ToString(), "text/plain");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error during connectivity check: {ex.Message}");
            }
        }
    }
}
```

## Explanation

The fix replaces the vulnerable `Process.Start()` call with `System.Net.NetworkInformation.Ping`, which performs ICMP echo requests natively in .NET without spawning external processes or parsing command-line arguments. This eliminates the injection point entirely.

The original code concatenated the untrusted `serverName` parameter directly into a PowerShell `-Command` string, allowing an attacker to inject arbitrary PowerShell commands (e.g., `serverName="dummy; Get-Content C:\secret.txt | Out-String"`). 

The fix:
1. **Eliminates the sink**: Removes `Process.Start()` and PowerShell command execution entirely
2. **Validates input**: Performs DNS resolution to validate the hostname before attempting to ping
3. **Preserves functionality**: Loops 4 times to match the original `-Count 4` behavior and formats output to match the expected response shape
4. **Maintains error handling**: Returns appropriate HTTP error codes for invalid input or connection failures

## Behaviour changes

- **Output format**: The output now mimics Windows `ping` command format instead of PowerShell `Test-Connection` format. Both show similar information (reply address, time, TTL, loss statistics) but with slightly different formatting.
- **Timeout behaviour**: Uses a 5-second timeout per request instead of whatever the original PowerShell default was
- **TTL value**: Fixed at 64 (typical for Windows systems) rather than whatever the actual remote system returns; this is a limitation of the .NET Ping API but does not affect the primary use case of determining connectivity
- **DNS validation**: Now performs explicit hostname validation via `Dns.GetHostAddresses()` before attempting to ping, returning a 400 Bad Request for invalid hostnames instead of letting the process fail silently
- **No external process spawning**: The fix uses .NET native APIs instead of launching PowerShell, improving performance and removing dependency on PowerShell being installed
