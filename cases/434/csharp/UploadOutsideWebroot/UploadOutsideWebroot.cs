using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases;

[ApiController]
public class UploadOutsideWebrootController : ControllerBase
{
    private readonly IWebHostEnvironment _env;

    public UploadOutsideWebrootController(IWebHostEnvironment env) => _env = env;

    [HttpPost("/upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest();
        }

        var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
        Directory.CreateDirectory(uploadRoot);

        // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
        var destination = Path.Combine(uploadRoot, file.FileName);

        await using var stream = System.IO.File.Create(destination);
        await file.CopyToAsync(stream);

        return Ok(new { stored = Path.GetFileName(destination), bytes = file.Length });
    }
}
