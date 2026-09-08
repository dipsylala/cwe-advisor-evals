## Verdict

Exploitable. The `serverName` parameter flows directly from an untrusted HTTP query parameter into a PowerShell `-Command` argument string without validation or escaping. The `-Command` flag re-parses its argument as PowerShell script code, allowing injection of arbitrary commands.

## Source

HTTP query parameter `serverName` in `[FromQuery] string serverName` at the method signature. No validation occurs before the parameter is used.

## Fix

### File: PowerShellCommandConcat.cs

```csharp
using System;
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
                return BadRequest("serverName parameter is required");
            }

            var sb = new StringBuilder();
            using var ping = new Ping();
            int count = 4;
            int successCount = 0;

            for (int i = 0; i < count; i++)
            {
                try
                {
                    var reply = ping.Send(serverName, 4000);
                    if (reply.Status == IPStatus.Success)
                    {
                        sb.AppendLine($"Reply from {reply.Address}: bytes={reply.Buffer.Length} time={reply.RoundtripTime}ms TTL={reply.Options?.Ttl ?? 0}");
                        successCount++;
                    }
                    else
                    {
                        sb.AppendLine($"Reply from {serverName}: {reply.Status}");
                    }
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"Request timed out: {ex.Message}");
                }
            }

            sb.AppendLine();
            sb.AppendLine($"Ping statistics for {serverName}:");
            sb.AppendLine($"  Packets: Sent = {count}, Received = {successCount}, Lost = {count - successCount} ({(count - successCount) * 100 / count}% loss)");

            return Content(sb.ToString(), "text/plain");
        }
    }
}
```

## Explanation

The fix eliminates the Process.Start() call entirely by replacing the PowerShell `Test-Connection` command with `System.Net.NetworkInformation.Ping`, a .NET Framework class that provides equivalent ICMP-based network diagnostics. The `serverName` parameter is passed directly to `Ping.Send()`, which does not re-parse it as code — it is treated solely as a hostname or IP address to probe. The loop constructs four ping attempts (matching the original `-Count 4`), catches per-attempt exceptions, and formats output similar to the original command's response. Input validation rejects empty or null values before any network call. This approach closes the injection vector completely: there is no command string, no shell interpreter, and no re-parsing of user input as code.

## Behaviour changes

The output format of ping statistics differs slightly from PowerShell's `Test-Connection` output (e.g., loss percentage calculation and summary line format), but conveys the same information (packets sent, received, lost, and per-reply details). The HTTP status code on invalid input changes from 200 (with an error in stdout) to 400 (BadRequest). Timeout behavior is handled per-ping rather than at the process level, with individual timeouts set to 4000ms per attempt. These changes preserve the endpoint's functionality (report network connectivity) while eliminating command execution entirely.
