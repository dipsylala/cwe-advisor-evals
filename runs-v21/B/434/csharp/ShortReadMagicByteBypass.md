## Verdict

exploitable

## Source

Attacker-controlled file uploaded via `IFormFile` parameter in the ASP.NET Core controller action `UploadAttachment`.

## Fix

### File: ShortReadMagicByteBypass.cs

```csharp
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

            if (bytesRead < header.Length)
            {
                return BadRequest("File is too short to contain a valid file signature.");
            }

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
```

## Explanation

The vulnerability lies in the magic-byte signature validation on lines 38-39. `Stream.Read()` may return fewer bytes than requested without error; it does not guarantee filling the entire buffer. If an attacker uploads a file shorter than 8 bytes, `bytesRead` will be less than 8, and the header array will contain uninitialized (zero) bytes in the remaining positions. The `SequenceEqual()` comparison then operates on these spurious bytes, potentially accepting files that should be rejected.

The fix adds a validation check immediately after the `Read()` call: if fewer than 8 bytes were read, the request is rejected with a `BadRequest` response. This enforces that the file contains sufficient data to validate a proper file signature, closing the CWE-434 weakness of unrestricted file uploads. The fix is minimal and focused on the specific defect: it does not change the overall design, but rather validates the precondition (full header present) before proceeding with the type check.

## Behaviour changes

The fix adds an early-return path: requests with files shorter than 8 bytes now return a 400 Bad Request response with the message "File is too short to contain a valid file signature." Previously, such short files would be compared against the signature bytes as if the remaining buffer positions (which contain zeros) were part of the uploaded file. This is the intended behaviour change to close the vulnerability. No other code paths or return values are affected. The method signature, error handling for null/empty files, storage path generation, and file writing all remain unchanged.
