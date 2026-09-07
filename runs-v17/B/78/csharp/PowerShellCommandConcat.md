## Verdict

Exploitable. The `serverName` query parameter is concatenated directly into a PowerShell `-Command` argument without sanitization. PowerShell re-parses the `-Command` argument as script code, permitting command injection. An attacker can supply `127.0.0.1; Remove-Item C:\file`, which PowerShell will execute as two separate commands.

## Source

Query parameter `serverName` from `[FromQuery] string serverName` (line 12), untrusted HTTP input.

## Fix

Replace Process.Start() with System.Net.NetworkInformation.Ping, eliminating process execution entirely and achieving the same connectivity-test goal the PowerShell command performed.

### File: PowerShellCommandConcat.cs

```csharp
using System;
using System.Diagnostics;
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
                return BadRequest("serverName cannot be empty");
            }

            try
            {
                var ping = new Ping();
                var options = new PingOptions { DontFragment = true };
                byte[] buffer = Encoding.ASCII.GetBytes("data");
                
                StringBuilder output = new StringBuilder();
                int successCount = 0;
                
                for (int i = 0; i < 4; i++)
                {
                    PingReply reply = ping.Send(serverName, 4000, buffer, options);
                    
                    if (reply.Status == IPStatus.Success)
                    {
                        output.AppendLine($"Reply from {reply.Address}: bytes=32 time={reply.RoundtripTime}ms TTL={reply.Options.Ttl}");
                        successCount++;
                    }
                    else
                    {
                        output.AppendLine($"Request timed out.");
                    }
                }
                
                output.AppendLine();
                output.AppendLine($"Ping statistics for {serverName}:");
                output.AppendLine($"Packets: Sent = 4, Received = {successCount}, Lost = {4 - successCount} ({(100 * (4 - successCount)) / 4}% loss)");
                
                return Content(output.ToString(), "text/plain");
            }
            catch (PingException ex)
            {
                return Content($"Destination unreachable: {ex.Message}", "text/plain");
            }
            catch (ArgumentException ex)
            {
                return BadRequest($"Invalid hostname or IP address: {ex.Message}");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error: {ex.Message}");
            }
        }
    }
}
```

## Explanation

The vulnerability arises because `serverName` is concatenated directly into the PowerShell command string passed via the `-Command` argument. PowerShell interprets `-Command` as a complete script and re-parses it, treating injected semicolons and command separators as script code boundaries. The fix eliminates process execution entirely by replacing the PowerShell command with the .NET Framework's `System.Net.NetworkInformation.Ping` class, which accomplishes the same goal—verifying connectivity to a remote host—without invoking any external process or interpreter. This follows the primary defence strategy in the CWE-78 guidance: eliminate OS command execution by using language-native APIs. The Ping class is available in all modern .NET versions and safely handles hostname resolution and ICMP operations without shell re-parsing or command injection risk.

## Behaviour changes

Output format changes from PowerShell Test-Connection output to standard Windows Ping output format (e.g., "Reply from 127.0.0.1: bytes=32 time=1ms TTL=64"). Error handling becomes more granular with explicit catch blocks for PingException (unreachable hosts) and ArgumentException (invalid hostnames). The method now sends four ICMP echo requests sequentially instead of using WMI, which may have minor latency and behavior differences but achieves the same connectivity verification purpose. The endpoint now validates for empty input and returns a 400 BadRequest response for null or whitespace hostnames, providing early rejection of invalid requests.
