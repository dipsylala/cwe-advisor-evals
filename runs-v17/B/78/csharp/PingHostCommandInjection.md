## Verdict

VULNERABLE. Line 22 passes untrusted user input concatenated into a command string to Process.Start, allowing arbitrary OS command injection. The purpose of the code (network diagnostics) is incidental and can be replaced entirely with .NET's native Ping class, eliminating the sink.

## Source

The `host` query parameter (line 11, `[FromQuery] string host`) flows directly into the ProcessStartInfo Arguments field (line 16: `Arguments = "/c ping -n 4 " + host`) without validation. An attacker can inject shell metacharacters or commands.

## Fix

### File: PingHostCommandInjection.cs

```csharp
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DiagnosticsController : ControllerBase
    {
        [HttpGet("ping")]
        public IActionResult PingHost([FromQuery] string host)
        {
            // Input validation: reject if empty or contains shell metacharacters
            if (string.IsNullOrWhiteSpace(host))
            {
                return BadRequest("Host parameter is required");
            }

            // Use strict allowlist: alphanumeric, dots, and hyphens (valid for IPs and hostnames)
            // Anchor with \A and \z to prevent newline injection
            if (!Regex.IsMatch(host, @"\A[a-zA-Z0-9.\-]+\z"))
            {
                return BadRequest("Invalid host parameter");
            }

            // Use .NET's Ping class instead of executing the ping command
            using var ping = new Ping();
            
            try
            {
                var reply = ping.Send(host, timeout: 4000);
                
                // Format output similar to the original ping command
                if (reply.Status == IPStatus.Success)
                {
                    string output = $"Reply from {reply.Address}: bytes={reply.Buffer.Length} time={reply.RoundtripTime}ms TTL={reply.Options.Ttl}";
                    return Content(output, "text/plain");
                }
                else
                {
                    string output = $"Ping to {host} failed: {reply.Status}";
                    return Content(output, "text/plain");
                }
            }
            catch (PingException ex)
            {
                return Content($"Error: {ex.Message}", "text/plain");
            }
        }
    }
}
```

## Explanation

The fix replaces Process.Start() with System.Net.NetworkInformation.Ping, which is .NET's native network diagnostics API. This eliminates the injection sink entirely: there is no command string construction, no shell parsing, and no opportunity for argument injection.

Input validation (strict allowlist accepting only hostname and IP address characters) provides secondary defense against edge cases where name resolution might be abused, anchored with `\A` and `\z` to prevent newline injection per .NET guidance.

The output format is preserved to maintain backward compatibility with callers expecting ping-like response text.

## Behaviour changes

- Removes all OS command execution; the endpoint no longer spawns cmd.exe or any external process
- Input validation now rejects host parameters containing shell metacharacters (`;`, `|`, `&`, newlines, spaces, etc.), returning a 400 Bad Request instead
- Timeout is now 4000ms (4 seconds) via Ping.Send timeout parameter instead of ping command-line control
- Response format changes slightly from `cmd.exe /c ping` output to .NET Ping class output format (same essential information: source address, bytes, roundtrip time, TTL)
- Errors from Ping (PingException) are caught and returned as text responses instead of process stderr
- The endpoint now uses only managed .NET APIs with no dependency on platform binaries
