## Verdict

Confirmed. `PingHost` builds `cmd.exe /c ping -n 4 <host>` by string-concatenating the unvalidated `host` query parameter into `ProcessStartInfo.Arguments`, then runs it via `Process.Start`. Any shell metacharacter in `host` (e.g. `& calc.exe`, `; type C:\secrets.txt`, `| whoami`, backtick/`$()` equivalents `cmd.exe` honors) is interpreted by the shell, giving arbitrary command execution with the web process's privileges.

## Source

`host` — bound from the query string via `[FromQuery] string host` on the `GET api/diagnostics/ping` action (`PingHostCommandInjection.cs`, line 11). It flows unmodified into `psi.Arguments` (line 16) and is executed at the `Process.Start(psi)` sink (line 22).

## Fix

### File: PingHostCommandInjection.cs
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
            if (string.IsNullOrWhiteSpace(host) ||
                Uri.CheckHostName(host) == UriHostNameType.Unknown)
            {
                return BadRequest("host must be a valid hostname or IP address.");
            }

            var psi = new ProcessStartInfo
            {
                FileName = "ping",
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            psi.ArgumentList.Add("-n");
            psi.ArgumentList.Add("4");
            psi.ArgumentList.Add(host);

            using var process = Process.Start(psi);

            string output = process!.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return Content(output, "text/plain");
        }
    }
}
```

## Explanation

Two changes, both required:

1. **No shell, and arguments passed as an array, not a string.** `FileName` is now `ping` itself instead of `cmd.exe /c ...`, and `UseShellExecute = false` with `ArgumentList` entries (`"-n"`, `"4"`, `host`) means each element reaches `ping`'s argv as one opaque token. .NET's `Process` on Windows escapes each `ArgumentList` entry per Win32 `CommandLineToArgvW` rules before building the underlying command line, so shell metacharacters such as `&`, `|`, `;`, backticks, or `$()` in `host` are passed through literally as data — there is no shell process left to interpret them, closing the injection that string-concatenating into `cmd.exe /c` created.

2. **Structural validation closes the remaining flag-injection gap.** An argument array alone stops shell metacharacter injection, but `ping` still parses its own argv, so a `host` value starting with `-` (e.g. `-t` for a permanent flood, or an unrecognized switch) would still be read as an option rather than a target. `Uri.CheckHostName(host)` (from `System.Net`, in `System.Private.Uri`/BCL, no extra dependency) validates that the value is structurally a valid DNS hostname, IPv4, or IPv6 address per RFC syntax; such a value cannot begin with `-`, so this rejects the flag-injection case as a side effect of confirming the value is actually a host, not by pattern-matching against dangerous characters. This is used because the endpoint's own contract already constrains the field to "a pingable host," so validating against that real format is not an incidental security-only allowlist — it's the value's defined shape, and rejecting anything else does not narrow legitimate use.

The output stream and behavior for a legitimate hostname or IP are unchanged.
