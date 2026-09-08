## Verdict

Exploitable. `PingHost` builds `cmd.exe /c ping -n 4 <host>` by string concatenation and runs it via `Process.Start`. `host` comes straight from `[FromQuery] string host` with no validation, so a value such as `127.0.0.1 & calc.exe` or `127.0.0.1 & type C:\secret.txt` is passed to `cmd.exe`, which splits on `&`/`|`/`&&` and executes the attacker-supplied command with the web process's privileges.

## Source

`host` - the `[FromQuery] string host` parameter of `DiagnosticsController.PingHost` (`GET api/Diagnostics/ping?host=...`). Fully attacker-controlled, no framework model-binding constraint restricts its shape.

## Fix

### File: PingHostCommandInjection.cs

```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DiagnosticsController : ControllerBase
    {
        // RFC 1123 hostname: dot-separated labels of 1-63 chars, alphanumeric with internal
        // hyphens only, no leading/trailing hyphen, 253 chars overall. Anchored with \A/\z so a
        // trailing newline cannot slip past the check the way ^/$ would allow.
        private static readonly Regex HostnamePattern = new Regex(
            @"\A(?=.{1,253}\z)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\z",
            RegexOptions.Compiled);

        [HttpGet("ping")]
        public IActionResult PingHost([FromQuery] string host)
        {
            if (!TryGetCanonicalHost(host, out var canonicalHost))
            {
                return BadRequest("host must be a valid IPv4/IPv6 address or hostname.");
            }

            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "PING.EXE"),
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            psi.ArgumentList.Add("-n");
            psi.ArgumentList.Add("4");
            psi.ArgumentList.Add(canonicalHost);

            // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
            using var process = Process.Start(psi);

            string output = process!.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return Content(output, "text/plain");
        }

        private static bool TryGetCanonicalHost(string? host, out string canonicalHost)
        {
            canonicalHost = string.Empty;
            if (string.IsNullOrWhiteSpace(host))
            {
                return false;
            }

            // Round-trip the parse: IPAddress.TryParse accepts non-canonical forms (octal-looking
            // octets, short-form IPv4) and normalizes them, so a naive TryParse-only check would let
            // through a value that prints differently than what was validated.
            if (IPAddress.TryParse(host, out var parsedIp) && parsedIp.ToString() == host)
            {
                canonicalHost = host;
                return true;
            }

            if (HostnamePattern.IsMatch(host))
            {
                canonicalHost = host;
                return true;
            }

            return false;
        }
    }
}
```

## Explanation

This is the "the command's output is the feature" case, not the "command is incidental" case: the endpoint's entire purpose is to return `ping`'s per-reply table as `text/plain`, and no .NET class reproduces that (`System.Net.NetworkInformation.Ping.Send()` returns a single structured `PingReply`, not a four-echo text table), so the fix keeps executing `ping.exe` and makes the execution safe instead of replacing it. Three changes close the injection without touching that output contract. First, `cmd.exe /c "... " + host` is replaced with launching `PING.EXE` directly (no shell) via `ArgumentList`, so the value can never be interpreted as additional shell syntax - `&`, `|`, `&&`, `;` become literal, meaningless characters inside a single argument rather than command separators. Second, the executable is resolved through `Environment.SystemDirectory` to an absolute path, so a writable `PATH` entry earlier in search order cannot substitute a different `ping` binary. Third, `host` is validated against an allowlist format the application owns - a canonical IPv4/IPv6 address (round-tripped through `IPAddress.ToString()` to reject ambiguous forms like octal-looking octets) or an RFC 1123 hostname - before it is used, and the validated value itself (not the raw input) is what is passed to `ArgumentList`. That format allowlist also incidentally closes the separate argument-injection angle (CWE-88): a value beginning with `-` can never match either allowed shape, so `ping.exe` - which does not honor a `--` end-of-options marker - can never be handed something it would parse as a switch.

## Behaviour changes

- Invalid `host` values (anything that is not a canonical IPv4/IPv6 address or a valid RFC 1123 hostname) now return `400 Bad Request` instead of being handed to `cmd.exe`. This is the intended effect of the fix, not a side effect - the original had no rejection path at all.
- The success-path output is unchanged: same binary (`ping.exe`), same flags (`-n 4`), same target semantics, same `StandardOutput` text returned as `text/plain`. `RedirectStandardOutput`, `UseShellExecute = false`, and the read/wait/return sequence are preserved exactly from the original; stderr is still not captured, matching the original's behavior.
- A legitimate but non-canonically-formatted address (e.g. an IPv6 literal with a leading-zero group, or an IPv4 octal-style octet) is now rejected rather than silently reformatted and pinged, per the guidance's round-trip check. This trades a small amount of input flexibility for closing the ambiguity the unfixed code had no defense against.

## Verification

Compiled with the .NET 10 SDK (`dotnet build`) against `net8.0` with an ASP.NET Core Web SDK project referencing `Microsoft.AspNetCore.App` (so `ControllerBase`, `ApiController`, and the MVC types resolve), in a scratch directory outside the repo. Build succeeded: 0 warnings, 0 errors. Every new symbol was checked against this build and the referenced APIs: `Path.Combine`/`Environment.SystemDirectory` (`System.IO`/`System`), `IPAddress.TryParse` (`System.Net`), `Regex`/`RegexOptions.Compiled` (`System.Text.RegularExpressions`), and `ProcessStartInfo.ArgumentList` (`System.Diagnostics`, available on .NET Core 2.1+/.NET 5+, which this ASP.NET Core project targets) - all present in the loaded C#/CWE-78 guidance or the standard library.

Assumption: the project targets .NET Core/.NET 5+ (not .NET Framework), inferred from the ASP.NET Core `[ApiController]`/`Microsoft.AspNetCore.Mvc` usage already in the file - `ArgumentList` requires that target and is absent on .NET Framework.
