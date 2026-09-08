## Verdict
CWE-78 OS Command Injection is confirmed. The `host` query parameter is concatenated directly into a cmd.exe command line without validation, allowing attackers to inject shell metacharacters and execute arbitrary OS commands.

## Source
**File:** PingHostCommandInjection.cs  
**Line:** 11 (input source), 16 (concatenation point), 22 (sink)

Attacker-controlled input: `host` parameter from HTTP query string (line 11: `[FromQuery] string host`)

Data flow:
1. `host` parameter received from query
2. Concatenated into command string at line 16: `Arguments = "/c ping -n 4 " + host`
3. Passed to ProcessStartInfo and invoked at line 22: `Process.Start(psi)`

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
The injection vulnerability arose from concatenating the untrusted `host` parameter into a command line string, which cmd.exe then parses. An attacker could inject shell metacharacters (`;`, `&`, `||`, `&&`, `|`) to execute arbitrary commands.

The fix eliminates the shell interpretation entirely by:

1. **Removing cmd.exe as the FileName** — the original used `"cmd.exe"` as the executable with `/c` to spawn a shell interpreter. Passing control to cmd.exe means cmd.exe parses the entire argument line and can execute attacker-injected commands.

2. **Invoking ping.exe directly** — FileName is now `"ping.exe"`, which is invoked directly without shell interpretation.

3. **Using ArgumentList instead of string concatenation** — individual arguments (`-n`, `4`, and `host`) are added to the ArgumentList collection rather than concatenated into a single Arguments string. ArgumentList passes arguments as a separate array to the process, preventing cmd.exe-style parsing. Each argument is treated as an atomic unit.

4. **Explicit UseShellExecute = false** — confirms that no command shell will interpret the arguments.

The `host` parameter now reaches ping.exe as a literal argument. If an attacker injects `google.com; dir`, ping.exe receives that as the hostname to resolve, fails to look it up, and the semicolon is never interpreted as a command separator. The injection is neutralized.

The output format and behavior remain identical for legitimate input.

## Behaviour changes
- **Command execution path:** Changed from `cmd.exe /c ping -n 4 {host}` to direct invocation of `ping.exe` with separate arguments.
- **Attack surface:** Shell metacharacters in the `host` parameter are no longer interpreted as operators. An attacker-supplied `host` value like `8.8.8.8; whoami` is passed to ping.exe as-is (as the hostname), ping fails to resolve it, and no command execution occurs.
- **Output:** Identical to the original for valid hostnames. Invalid hostnames (containing metacharacters) now fail cleanly with a "Unknown host" or resolution error from ping.exe instead of being partially executed as commands.
- **Arguments library API:** ArgumentList is available in .NET Core 2.1+, .NET Standard 2.1+, and .NET 5+. On .NET Framework (absent ArgumentList), hand-escaping `Arguments` would be required instead, but the codebase uses ASP.NET Core (modern runtime), so ArgumentList is available.
