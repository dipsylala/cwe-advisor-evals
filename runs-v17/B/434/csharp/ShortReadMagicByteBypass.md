## Verdict

Exploitable. The code calls `stream.Read()` without ensuring all requested bytes are actually read before performing signature validation. `Stream.Read()` can return fewer bytes than requested, leaving the buffer partially filled with zeros. The signature comparison at lines 38-39 operates on bytes that may not have been read from the file, allowing validation bypass through short reads.

## Source

Attacker-controlled uploaded file via `IFormFile file` parameter at line 25.

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
            try
            {
                await stream.ReadAtLeastAsync(header, header.Length);
            }
            catch (EndOfStreamException)
            {
                return BadRequest("File is too short to be a valid document.");
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

            return Ok(new { storedName, bytesRead = header.Length, length = file.Length });
        }
    }
}
```

## Explanation

The fix replaces the unsafe `stream.Read()` call with `stream.ReadAtLeastAsync()`, which guarantees that either all requested bytes are read from the stream or an exception is thrown. This ensures the header buffer is completely filled with actual file content before signature validation. The try-catch block handles the case where the uploaded file is too short to contain a valid signature, returning a 400 Bad Request instead of allowing validation to proceed on a partially-filled buffer. By guaranteeing all 8 header bytes are read before comparison, the signature check now operates on complete file content rather than zero-padded defaults, eliminating the bypass vector.

## Behaviour changes

- **async/await addition**: Changed from synchronous `stream.Read()` to asynchronous `stream.ReadAtLeastAsync()`. No functional change to callers since the action method is already async; this is the correct pattern for ASP.NET Core uploads.
- **Exception handling**: Added try-catch for `EndOfStreamException`. Files shorter than 8 bytes now return a 400 error with a descriptive message instead of silently proceeding with a zero-padded buffer. This is the correct behavior for rejecting malformed uploads.
- **Removed unused bytesRead variable**: The original code captured `bytesRead` but never used it. `ReadAtLeastAsync()` guarantees all bytes are read, so the variable was removed. The response object references `header.Length` as a constant instead, preserving the response schema.
