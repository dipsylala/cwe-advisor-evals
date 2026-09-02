## Verdict

exploitable (confidence: high)

CWE-78 - Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'). The `host` query parameter reaches `cmd.exe /c ping -n 4 <host>` through direct string concatenation with no validation or encoding anywhere on the path, so an attacker-supplied value such as `127.0.0.1 & calc.exe` or `127.0.0.1 & type C:\secrets.txt` is passed straight to a spawned command shell.

## Source

`host` - the `[FromQuery] string host` parameter of `DiagnosticsController.PingHost` (`PingHostCommandInjection.cs`, line 11), an HTTP query-string value fully controlled by the caller.

## Fix

Vulnerable code:

```csharp
using System.Diagnostics;
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
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c ping -n 4 " + host,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };

            // SAST FINDING: CWE-78 reported here. Sink is the next statement.
            using var process = Process.Start(psi);

            string output = process!.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return Content(output, "text/plain");
        }
    }
}
```

Fixed code:

```csharp
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DiagnosticsController : ControllerBase
    {
        // Hostname / IPv4 literal only - anchored with \A/\z (not ^/$) so a trailing
        // newline cannot slip a match past the check.
        private static readonly Regex HostPattern = new Regex(
            @"\A[A-Za-z0-9]([A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?\z", RegexOptions.Compiled);

        [HttpGet("ping")]
        public IActionResult PingHost([FromQuery] string host)
        {
            if (string.IsNullOrWhiteSpace(host) || !HostPattern.IsMatch(host))
            {
                return BadRequest("Invalid host.");
            }

            var output = new StringBuilder();
            using var ping = new Ping();

            for (int i = 0; i < 4; i++)
            {
                try
                {
                    PingReply reply = ping.Send(host, 4000);
                    if (reply.Status == IPStatus.Success)
                    {
                        output.AppendLine(
                            $"Reply from {reply.Address}: bytes={reply.Buffer.Length} " +
                            $"time={reply.RoundtripTime}ms TTL={reply.Options?.Ttl}");
                    }
                    else
                    {
                        output.AppendLine($"Request failed: {reply.Status}");
                    }
                }
                catch (PingException ex)
                {
                    output.AppendLine($"Ping error: {ex.Message}");
                    break;
                }
            }

            return Content(output.ToString(), "text/plain");
        }
    }
}
```

## Explanation

The command is incidental here - the endpoint's purpose is an ICMP reachability check, and .NET provides that natively via `System.Net.NetworkInformation.Ping`, so the primary fix is to eliminate `Process.Start`/`ProcessStartInfo` and `cmd.exe` entirely rather than try to escape or parameterize the shell invocation. `Ping.Send` issues the ICMP echo itself; the `host` string never becomes part of a command line or reaches any shell, which removes the injection sink rather than mitigating it. A strict allowlist regex (letters, digits, `.` and `-`, anchored with `\A`/`\z`) is kept as a secondary defence per the guidance, both to reject obviously malformed input early with a clear `400` and to guard against the value being reused in a future sink; it is not what stops the injection - the absence of a shell is.

## Behaviour changes

- Loop of four `ping.Send` calls with a 4000ms timeout replaces `-n 4`, reproducing the "4 echoes" behaviour of the original command but without the shell.
- Output text is now generated line-by-line (`Reply from ... / Request failed: ...`) by the fix instead of being the literal stdout of the Windows `ping.exe` binary - the reported fields (source address, reply size, round-trip time, TTL) are chosen to match what the original console output conveyed, but the exact text format differs. Any caller that parses the response body for the literal `ping.exe` text format will need to adapt.
- Malformed/empty `host` now returns `400 Bad Request` instead of being handed to `cmd.exe`, where it previously produced either a shell error, unexpected command execution, or a Windows "could not find host" message inside a `200` response. This is a new, intentional validation path, not a behaviour the original code exercised safely.
- A `PingReply.Status != Success` (e.g. `TimedOut`, `DestinationHostUnreachable`) or a `PingException` (e.g. DNS resolution failure) now produces a descriptive line and, for the exception case, stops the loop early - the original `ping.exe` would print its own equivalent message per attempt and continue for all 4 attempts regardless. Exit code / process-level failure handling is no longer applicable since no process is spawned.
- `RedirectStandardOutput`/`UseShellExecute` and the `process!` null-forgiving dereference are removed as inapplicable once `Process.Start` is eliminated.
