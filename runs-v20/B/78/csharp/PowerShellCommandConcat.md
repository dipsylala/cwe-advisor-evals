## Verdict

CWE-78, exploitable. Confidence: high.

Location: `PowerShellCommandConcat.cs`, line 22 (`Process.Start(psi)`), fed by the `Arguments` string built on line 16.

## Source

`serverName`, bound from the query string via `[FromQuery] string serverName` on `CheckConnectivity`. It is fully attacker-controlled and reaches the sink with no validation or encoding.

It flows directly into `ProcessStartInfo.Arguments = "-Command \"Test-Connection " + serverName + " -Count 4\""`, then to `Process.Start(psi)` on line 22, which launches `powershell.exe -Command "Test-Connection <serverName> -Count 4"`. `powershell.exe -Command` re-parses its argument as a script, so a value such as `x"; Remove-Item C:\ -Recurse -Force; "` closes the quoted string and appends arbitrary PowerShell commands that run with the same privileges as the ASP.NET Core process (the route is under `api/admin`, so likely elevated).

Sink contract: `Process.Start` returns a `Process`; the caller reads `StandardOutput` to end and calls `WaitForExit()`, then returns that text verbatim as the HTTP response body (`text/plain`). `RedirectStandardError` is left at its default (`false`), so stderr is not captured — that is unchanged by the fix. Exit code is not checked. `UseShellExecute` is already `false` (a graphical-shell setting only; it does not prevent `powershell.exe` itself from acting as a command interpreter).

## Fix

The endpoint's purpose is to run `Test-Connection` and return its output, so removing process execution would be a regression, not a remediation. The command itself is legitimate; the injection point is that a user-controlled string is spliced into a `-Command` argument that PowerShell re-parses as script text. The fix keeps `Test-Connection` and its table output, but stops building script text from user input: it moves the invocation to a fixed local script executed with `-File`, passing the server name in as a declared script parameter (data, not script text) via `ArgumentList`, and it validates the value as a hostname or IP address before use, since a server name is a value the application owns the format of. `IPAddress.TryParse` alone is not a validator (it accepts `010.1.1.1` and normalizes `8.8.8` to `8.8.0.8`), so the parsed value's `ToString()` is compared back against the original input and rejected on mismatch.

### File: PowerShellCommandConcat.cs

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
    [Route("api/admin/[controller]")]
    public class ServerDiagnosticsController : ControllerBase
    {
        private static readonly Regex HostnamePattern = new Regex(
            @"\A(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\z",
            RegexOptions.Compiled);

        private static readonly string ScriptPath = Path.Combine(AppContext.BaseDirectory, "Scripts", "TestConnectivity.ps1");

        [HttpGet("connectivity")]
        public IActionResult CheckConnectivity([FromQuery] string serverName)
        {
            if (string.IsNullOrWhiteSpace(serverName) || serverName.Length > 253 || !IsValidServerName(serverName))
            {
                return BadRequest("serverName must be a valid hostname or IP address.");
            }

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            psi.ArgumentList.Add("-File");
            psi.ArgumentList.Add(ScriptPath);
            psi.ArgumentList.Add("-ServerName");
            psi.ArgumentList.Add(serverName);

            // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
            using var process = Process.Start(psi);

            string output = process!.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return Content(output, "text/plain");
        }

        private static bool IsValidServerName(string value)
        {
            if (IPAddress.TryParse(value, out var parsed))
            {
                return parsed.ToString() == value;
            }

            return HostnamePattern.IsMatch(value);
        }
    }
}
```

### File: Scripts/TestConnectivity.ps1

```powershell
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName
)

Test-Connection -ComputerName $ServerName -Count 4
```

## Explanation

The vulnerability was that `serverName` was concatenated into the text of a `powershell.exe -Command` argument, which PowerShell re-parses as script — string concatenation there is equivalent to building a SQL query by concatenation, and any shell metacharacter or quote in the input lets an attacker append arbitrary commands. The fix keeps `powershell.exe` and the `Test-Connection` cmdlet (removing the command would remove the feature the endpoint provides) but changes how the value reaches PowerShell: `-File <fixed script path>` runs a script whose text is fixed and never touches user input, and `serverName` is passed as a separate `ArgumentList` entry bound to the script's own `-ServerName` parameter. PowerShell parameter binding treats that value as data assigned to a variable, not as script text to interpret, which is what closes the injection (per the loaded C# guidance: `-File` is what stops the value being re-parsed as script; `ArgumentList` alone does not help against a target that itself re-parses its command line). Hostname/IP format validation is added as the secondary, application-owned-format defense the guidance calls for, with the `IPAddress.TryParse` round-trip check the guidance flags as necessary since `TryParse` alone silently normalizes malformed octal/short forms.

## Behaviour changes

- **New validation / new response code**: requests with a `serverName` that is not a valid hostname or IP address (per `HostnamePattern` or the `IPAddress` round-trip check) now get `400 Bad Request` instead of being passed to PowerShell. Required because the value has no other constraint before reaching the sink; previously it was reachable and unvalidated. This narrows the accepted input to well-formed hostnames and IP addresses (including IPv6) and rejects everything else, including any value that previously happened to work only because a shell metacharacter had no injection effect.
- **Script relocated to a file**: `Test-Connection <name> -Count 4` now runs from `Scripts/TestConnectivity.ps1` via `-File` instead of inline via `-Command`. Same cmdlet, same `-Count 4`, same table-style stdout returned as `text/plain` — the sink's return value and content type are unchanged. This requires the script file to be deployed alongside the assembly (under `Scripts/` relative to `AppContext.BaseDirectory`); it is a new deployment artifact, not a behavior change in the response.
- **Added `-NoProfile` and `-NonInteractive`**: prevents a host PowerShell profile script from altering `Test-Connection`'s behavior and prevents the process from ever blocking on a prompt. Does not change the command run or its output for the intended case.
- **Unchanged**: `RedirectStandardError` remains unset (stderr still not captured), exit code is still unchecked, `UseShellExecute` remains `false`, and the response is still the raw `StandardOutput` text returned as `text/plain` — the sink's return/discard/failure contract from the original code is otherwise preserved.

Verification: the fixed controller was compiled with `dotnet build` against a scratch ASP.NET Core project (`Microsoft.NET.Sdk.Web`, `net8.0`, matching the file's `Microsoft.AspNetCore.Mvc` usings) — build succeeded with 0 errors, 0 warnings. Every new symbol (`System.Net.IPAddress`, `System.Text.RegularExpressions.Regex`, `System.IO.Path`, `System.AppContext.BaseDirectory`, `ProcessStartInfo.ArgumentList`) is a .NET base class library member, confirmed by the successful compile rather than by name alone. The `.ps1` file's syntax was reviewed by hand (no PowerShell parser was available in the sandbox); it uses only a single `param()` block and a direct cmdlet call, both standard PowerShell script syntax.

Assumption: the project targets .NET Core/.NET 5+ (inferred from `Microsoft.AspNetCore.Mvc` and the single-file case, consistent with `ProcessStartInfo.ArgumentList` being available), not .NET Framework, where `ArgumentList` does not exist.
