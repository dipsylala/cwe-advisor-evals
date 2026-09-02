using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace UploadDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DocumentUploadController : ControllerBase
    {
        private static readonly byte[] PngSignature = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
        private static readonly byte[] PdfSignature = { 0x25, 0x50, 0x44, 0x46, 0x2D };

        private readonly string _storageRoot;

        public DocumentUploadController(IWebHostEnvironment env)
        {
            _storageRoot = Path.Combine(env.ContentRootPath, "private-uploads");
        }

        [HttpPost("attachments")]
        [RequestSizeLimit(10_000_000)]
        public async Task<IActionResult> UploadAttachment(IFormFile file)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest("No file supplied.");
            }

            using var stream = file.OpenReadStream();

            var header = new byte[8];
            // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
            int bytesRead = stream.Read(header, 0, header.Length);

            bool isPng = header.AsSpan(0, PngSignature.Length).SequenceEqual(PngSignature);
            bool isPdf = header.AsSpan(0, PdfSignature.Length).SequenceEqual(PdfSignature);

            if (!isPng && !isPdf)
            {
                return BadRequest("Unsupported file type.");
            }

            stream.Seek(0, SeekOrigin.Begin);

            Directory.CreateDirectory(_storageRoot);
            var storedName = Guid.NewGuid().ToString("N") + (isPng ? ".png" : ".pdf");
            var destinationPath = Path.Combine(_storageRoot, storedName);

            await using var destination = new FileStream(destinationPath, FileMode.CreateNew);
            await stream.CopyToAsync(destination);

            return Ok(new { storedName, bytesRead, length = file.Length });
        }
    }
}
