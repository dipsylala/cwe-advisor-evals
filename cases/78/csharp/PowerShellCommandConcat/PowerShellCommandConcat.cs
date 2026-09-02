using System.Diagnostics;
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
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-Command \"Test-Connection " + serverName + " -Count 4\"",
                UseShellExecute = false,
                RedirectStandardOutput = true
            };

            // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
            using var process = Process.Start(psi);

            string output = process!.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return Content(output, "text/plain");
        }
    }
}
