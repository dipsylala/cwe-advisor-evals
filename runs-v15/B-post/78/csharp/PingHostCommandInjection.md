## Verdict

EXPLOITABLE. Untrusted user input from the query parameter `host` is concatenated directly into a shell command string and passed to `Process.Start()`, allowing arbitrary OS command execution.

## Source

Query parameter `host` at line 11: `public IActionResult PingHost([FromQuery] string host)`. This value is attacker-controlled and unconstrained.

## Fix

Replace `Process.Start()` with the native `System.Net.NetworkInformation.Ping` API. This eliminates OS command execution entirely, closing the injection vector.

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
            if (string.IsNullOrWhiteSpace(host))
            {
                return BadRequest("Host parameter is required");
            }

            try
            {
                using var ping = new Ping();
                var reply = ping.Send(host, 4000);
                
                string output;
                if (reply.Status == IPStatus.Success)
                {
                    output = $"Reply from {reply.Address}: bytes={reply.Buffer.Length} time={reply.RoundtripTime}ms TTL={reply.Options.Ttl}\n";
                }
                else
                {
                    output = $"Ping to {host} failed: {reply.Status}\n";
                }
                
                return Content(output, "text/plain");
            }
            catch (PingException ex)
            {
                return BadRequest($"Ping failed: {ex.Message}");
            }
        }
    }
}
```

## Explanation

The original code spawned `cmd.exe /c ping -n 4 <host>`, concatenating untrusted input directly into the shell command string. An attacker could inject shell metacharacters (e.g., `8.8.8.8 & whoami`) to execute arbitrary commands with the application's privileges.

The fix replaces process execution with `System.Net.NetworkInformation.Ping`, a built-in .NET API that performs the same operation without involving a shell interpreter. The `Ping` class accepts a hostname or IP address string and returns timing and status information directly as a `PingReply` object. Input is no longer parsed as a shell command—it is passed as a parameter to a typed API, eliminating the injection attack surface entirely.

The fix adds null/whitespace validation on the input parameter to reject malformed requests early. Error handling via `PingException` preserves the original contract of returning a textual result; successful and failed pings both return plaintext output similar to the `ping` command's output.

## Behaviour changes

- **Removed**: Shell process invocation (`cmd.exe /c`), stdout redirection, and process lifetime management
- **Added**: Input validation (null/whitespace check), structured exception handling for network errors
- **Changed**: Output format slightly—single response line from Ping API replaces potentially multi-line `ping` command output, but communicates the same essential information (success/failure, latency, TTL)
- **Preserved**: HTTP response content type (text/plain), error responses (BadRequest on invalid input or network error)
