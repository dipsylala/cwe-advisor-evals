## Verdict

Exploitable. The `host` parameter from the HTTP query string is concatenated directly into a command string executed via `cmd.exe /c`, allowing OS command injection.

## Source

File: PingHostCommandInjection.cs, line 11 (source entry point: `[FromQuery] string host`)

Data flow:
1. Line 11: Untrusted `host` value enters as HTTP query parameter
2. Line 16: Value concatenated into Arguments string: `"/c ping -n 4 " + host`
3. Line 22: Command executed via `Process.Start(psi)` with shell interpreter

## Fix

The fix replaces the vulnerable `cmd.exe` invocation with a direct call to `ping.exe`, passing arguments separately via `ArgumentList` instead of string concatenation. This removes the shell interpreter and prevents shell metacharacter injection.

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
            var psi = new ProcessStartInfo
            {
                FileName = "ping.exe",
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

The original code invoked `cmd.exe /c` with a concatenated command string, allowing shell metacharacters in the `host` parameter to inject additional commands (e.g., `?host=google.com & whoami`). The fix removes `cmd.exe` entirely and calls `ping.exe` directly as the executable. Arguments are passed via `ArgumentList` (a collection property) where each argument is added separately, preventing shell re-parsing. This achieves the same ping behavior—sending 4 echo requests and capturing output—without the injection vector. `ArgumentList` is available in .NET Core 2.1, .NET Standard 2.1, and later; `UseShellExecute = false` is explicitly set to ensure no shell reinterpretation occurs.

## Behaviour changes

None. The output of `ping.exe -n 4 <host>` is identical to the original `cmd.exe /c ping -n 4 <host>` command, so the HTTP response content remains unchanged. The change affects only how arguments are passed (array form instead of concatenated string), not what is executed or returned.
