## Verdict

Confirmed. `host` is taken directly from the query string and concatenated into a string that is executed via `cmd.exe /c`, so any shell metacharacter in `host` (`&`, `|`, `;`, `` ` ``, `$()`, etc.) lets an attacker run arbitrary commands with the privileges of the web process.

## Source

`host` — `[FromQuery] string host` parameter of `PingHost`, `PingHostCommandInjection.cs` line 11. Fully attacker-controlled, arrives unvalidated.

## Fix

```csharp
using System.Diagnostics;
using System.Net;
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
                return BadRequest("Invalid host.");
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

Two changes close the injection, and each is required independently:

1. **Stop invoking a shell.** The original code runs `cmd.exe /c ping -n 4 <host>`, so `cmd.exe` re-parses the whole argument string and treats shell metacharacters in `host` as command separators/substitutions. Launching `ping` directly (`FileName = "ping"`) with `UseShellExecute = false` removes the shell parser from the picture entirely — there is no interpreter left to give special meaning to `&`, `|`, `;`, backticks, or `$()`.

2. **Pass arguments as an array, not a concatenated string.** Even with the shell removed, building `Arguments = "-n 4 " + host` as a single string would still let `host` be split into extra arguments/flags by .NET's own argument-parsing rules (e.g. a value containing spaces or quotes). Using `psi.ArgumentList.Add(host)` passes `host` as one atomic argument to the child process, so it can never be reinterpreted as additional flags or a second command.

3. **Validate `host` before use.** `Uri.CheckHostName` rejects values that aren't a syntactically valid IPv4/IPv6 address or DNS hostname (empty strings, or values containing spaces, slashes, or other characters outside the hostname grammar), which also rules out a leading `-` being read as a `ping` flag. This is defense in depth on top of the argument-array fix, not a substitute for it: validation narrows the *content* of `host`, while `UseShellExecute = false` + `ArgumentList` narrows how that content can ever be *interpreted*.

The output stream handling (`RedirectStandardOutput`, `StandardOutput.ReadToEnd()`) is unchanged and remains safe — it only reads back what the child process prints, it does not execute anything.
