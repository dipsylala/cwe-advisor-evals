## Verdict

Real issue confirmed. The `serverName` parameter from the query string is concatenated directly into a PowerShell command without escaping, allowing command injection. An attacker can inject arbitrary PowerShell commands by passing `serverName` with malicious syntax like `google.com; Get-Process`.

## Source

```csharp
Arguments = "-Command \"Test-Connection " + serverName + " -Count 4\"",
```

The sink is `Process.Start(psi)` at line 22, which executes the injected command string.

## Fix

### File: PowerShellCommandConcat.cs

```csharp
using System.Diagnostics;
using System.Management.Automation;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("api/admin/[controller]")]
    public class ServerDiagnosticsController : ControllerBase
    {
        [HttpGet("connectivity")]
        public IActionResult CheckConnectivity([FromQuery] string serverName)
        {
            try
            {
                using var ps = PowerShell.Create();
                ps.AddCommand("Test-Connection")
                  .AddParameter("ComputerName", serverName)
                  .AddParameter("Count", 4);

                var results = ps.Invoke();
                string output = string.Join(System.Environment.NewLine, results.Select(r => r.ToString()));

                return Content(output, "text/plain");
            }
            catch (Exception ex)
            {
                return BadRequest($"Connectivity check failed: {ex.Message}");
            }
        }
    }
}
```

## Explanation

The fix replaces process invocation with direct PowerShell API calls via `System.Management.Automation.PowerShell`. The `AddParameter` method passes `serverName` as a structured parameter to the `Test-Connection` cmdlet, eliminating the need for shell string escaping and preventing injection. User-supplied input is never parsed as PowerShell syntax; it flows directly to the cmdlet as data. This approach is more secure and more idiomatic for C# code targeting PowerShell.
