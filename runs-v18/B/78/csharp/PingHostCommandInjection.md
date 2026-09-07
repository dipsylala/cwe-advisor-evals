## Verdict
exploitable

## Source
`host` parameter from query string (line 11 of PingHostCommandInjection.cs) - attacker-controlled input from HTTP request

## Fix
### File: PingHostCommandInjection.cs
```csharp
using System;
using System.Net.NetworkInformation;
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
            if (string.IsNullOrEmpty(host))
            {
                return BadRequest("Host is required");
            }

            try
            {
                using var ping = new Ping();
                var reply = ping.Send(host, 4000);
                
                string output = reply.Status switch
                {
                    IPStatus.Success => $"Reply from {reply.Address}: bytes=32 time={reply.RoundtripTime}ms TTL=64",
                    IPStatus.TimedOut => "Request timed out.",
                    _ => $"Ping failed: {reply.Status}"
                };
                
                return Content(output, "text/plain");
            }
            catch (PingException ex)
            {
                return StatusCode(500, $"Ping error: {ex.Message}");
            }
        }
    }
}
```

## Explanation
The original code was vulnerable to OS command injection because it concatenated the untrusted `host` parameter directly into the command string passed to `Process.Start()`: `Arguments = "/c ping -n 4 " + host`. An attacker could supply input like `8.8.8.8 & malicious-command` to execute arbitrary OS commands. The fix eliminates this vulnerability by replacing the `Process.Start()` call with `System.Net.NetworkInformation.Ping`, which is the built-in .NET class designed for ICMP echo requests. The Ping class does not invoke a shell and does not concatenate user input into command strings. User input is passed safely to the Ping API, which handles it without interpretation as a command. This follows the primary remediation strategy from CWE-78 guidance: eliminate OS command execution by using language-native library alternatives.

## Behaviour changes
- **Removed Process.Start and ProcessStartInfo**: No longer spawns cmd.exe or any external process; the operation is now performed entirely within managed .NET code.
- **Removed string concatenation with user input**: The vulnerable `Arguments = "/c ping -n 4 " + host` is eliminated entirely.
- **Added input validation**: Empty or null host parameter now returns a 400 BadRequest response instead of attempting the operation.
- **Explicit timeout**: Uses a 4000ms (4 second) timeout for the ping operation, whereas the original used implicit OS-level timeout behavior. This is appropriate for network diagnostics.
- **Formatted output**: Returns structured ping response (e.g., "Reply from 8.8.8.8: bytes=32 time=45ms TTL=64") instead of raw cmd.exe output. The format approximates standard ping command output for API clients.
- **Exception handling**: Added try-catch block to handle PingException and return 500 error on network failures, providing graceful error responses instead of allowing process exceptions to propagate.
- **Single echo request**: The Ping.Send() method sends one ICMP echo request (the original `-n 4` sent four). For a single API call, this is appropriate; if the original requirement was specifically four requests, that would require looping or different API usage.
