## Verdict
VULNERABLE. The host parameter is concatenated directly into a cmd.exe command string, allowing command injection.

## Source
Line 11: `string host` parameter from query string (untrusted user input).

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
            var psi = new ProcessStartInfo
            {
                FileName = "ping.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            
            // Use ArgumentList to safely pass arguments without shell interpretation
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
The original code passed the host parameter as a string argument to cmd.exe with the `/c` flag. This invokes a shell that interprets special characters and command separators, enabling OS command injection.

The fix removes the shell entirely by:
1. Setting `FileName` to `ping.exe` directly instead of `cmd.exe`
2. Using `ArgumentList` to pass arguments as a list rather than concatenating them into a string. ArgumentList automatically handles quoting and escaping, ensuring the host parameter is passed as a single argument value to ping.exe.
3. Removing the `/c` flag since we are no longer using a shell.

Since `UseShellExecute` is already `false`, the process will not spawn a shell, and the host value cannot be interpreted as a command. This eliminates the command injection vector while preserving the ping functionality.
