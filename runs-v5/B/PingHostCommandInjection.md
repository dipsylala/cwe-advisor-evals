## Verdict

CWE-78, exploitable. Confidence: high.

## Source

`host` from `[FromQuery] string host` on `PingHost` (`PingHostCommandInjection.cs:11`) - an unvalidated HTTP query parameter, fully attacker-controlled.

## Fix

**Vulnerable code** (`PingHostCommandInjection.cs:13-27`):

```csharp
var psi = new ProcessStartInfo
{
    FileName = "cmd.exe",
    Arguments = "/c ping -n 4 " + host,
    UseShellExecute = false,
    RedirectStandardOutput = true
};

// SAST FINDING: CWE-78 ... Sink is the next statement.
using var process = Process.Start(psi);

string output = process!.StandardOutput.ReadToEnd();
process.WaitForExit();

return Content(output, "text/plain");
```

`host` is concatenated directly into the `cmd.exe /c` argument string with no validation or escaping, so a value such as `127.0.0.1 & calc.exe` or `127.0.0.1 & type C:\secrets.txt` is interpreted by the shell, not by `ping`.

**Fixed code**:

```csharp
using System.Net.NetworkInformation;
using System.Text;
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
            var output = new StringBuilder();

            using var ping = new Ping();
            for (int i = 0; i < 4; i++)
            {
                PingReply reply;
                try
                {
                    reply = ping.Send(host, 4000);
                }
                catch (PingException)
                {
                    return BadRequest("Unable to resolve or reach the specified host.");
                }

                if (reply.Status == IPStatus.Success)
                {
                    output.AppendLine(
                        $"Reply from {reply.Address}: bytes={reply.Buffer.Length} " +
                        $"time={reply.RoundtripTime}ms TTL={reply.Options?.Ttl}");
                }
                else
                {
                    output.AppendLine($"Request to {host} failed: {reply.Status}");
                }
            }

            return Content(output.ToString(), "text/plain");
        }
    }
}
```

## Explanation

Pinging a host is a network operation .NET already exposes natively, so per the CWE-78 guidance the correct fix eliminates the command execution entirely rather than trying to sanitize the shell string. `System.Net.NetworkInformation.Ping.Send(string, int)` resolves the hostname and sends ICMP echo requests through the OS network stack directly - `host` never becomes a shell command, a process argument, or a `cmd.exe` invocation, so there is no injection point left to protect. This also removes the `.bat`/`cmd.exe`-re-parsing hazard the guidance calls out, since no shell is invoked at all. A `PingException` (unresolvable or malformed host) is caught and turned into a 400 response instead of the endpoint faulting.

## Behaviour changes

- Output format changed: the original returned raw `ping.exe` console text; the fix returns one summary line per echo reply (`Reply from ... time=...ms TTL=...` or a failure line) built from `PingReply` fields, since there is no longer an external command whose stdout can be captured verbatim. This is a necessary consequence of eliminating the sink, not an incidental change.
- Error handling added: an unresolvable or unreachable host now returns `400 Bad Request` instead of the original behavior (either raw ping-utility error text via `Content(output, ...)`, or an unhandled null-process crash if `cmd.exe`/`ping` were unavailable). This is a strict improvement, not a loss of prior functionality.
- Hostnames and literal IPs are both still accepted, matching the original `ping` command's behavior - no allowlist was added because the fix removes the sink rather than validating input for it.
- Assumption: the endpoint's purpose is network reachability/latency checking, so `System.Net.NetworkInformation.Ping` (the library alternative the loaded C# guidance names for this exact case) was used to replace the command rather than keeping `Process.Start` behind added validation.
