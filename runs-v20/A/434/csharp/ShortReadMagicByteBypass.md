## Verdict

Confirmed. The magic-byte file-type check trusts a single `Stream.Read` call to fill an 8-byte buffer. `Stream.Read` is permitted to return fewer bytes than requested even when the stream is not at EOF, and the code never checks `bytesRead` against the length it needs before running the PNG/PDF signature comparison. A stream that legitimately (or deliberately, via a slow/odd-chunked multipart body) delivers the header in more than one chunk causes the comparison to run against a buffer that instead of the file's real bytes past `bytesRead` uses whatever the freshly allocated array holds. Because the validation makes no distinction between "read the required signature" and "read less than needed," the type check is not evaluated reliably: this is the sink the scanner flagged, and it is the only gate in the method deciding whether the upload is accepted, so any code path that lets the comparison run on an incompletely populated buffer defeats the file-type restriction the endpoint depends on.

## Source

`IFormFile file` — the multipart file upload posted to `POST api/[controller]/attachments`, bound by the `UploadAttachment` action parameter. `file.OpenReadStream()` (line 32) is the attacker-controlled byte stream; its content and the chunking behavior of its backing implementation are outside the server's control.

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
            int totalRead = 0;
            while (totalRead < header.Length)
            {
                int read = await stream.ReadAsync(header.AsMemory(totalRead, header.Length - totalRead));
                if (read == 0)
                {
                    // Stream ended before the full header arrived; do not evaluate
                    // a signature match against the unread, zero-filled remainder.
                    break;
                }
                totalRead += read;
            }

            bool isPng = totalRead >= PngSignature.Length &&
                header.AsSpan(0, PngSignature.Length).SequenceEqual(PngSignature);
            bool isPdf = totalRead >= PdfSignature.Length &&
                header.AsSpan(0, PdfSignature.Length).SequenceEqual(PdfSignature);

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

            return Ok(new { storedName, bytesRead = totalRead, length = file.Length });
        }
    }
}
```

## Explanation

The single-call `stream.Read(header, 0, header.Length)` assumes the stream fills the buffer in one shot. Per the documented `Stream.Read` contract, an implementation is free to return anywhere from 1 up to the requested count even when more data is available and the stream has not reached EOF — this is normal, spec-conformant behavior for many stream types, not just network sockets. The method used `bytesRead` only for the response payload, never to gate the comparison, so `header.AsSpan(0, PngSignature.Length)`/`AsSpan(0, PdfSignature.Length)` ran unconditionally over a buffer that could be partly the freshly-allocated array's zero default rather than the file's actual bytes, making the type decision depend on how the runtime happened to chunk the read rather than on the file's real content.

The fix loops on `ReadAsync` until either the full 8-byte header has been assembled or the stream signals end-of-data (a `0`-byte read), so `totalRead` always reflects how many genuine bytes were obtained. Each signature comparison is additionally guarded by `totalRead >= <signature length>`, so a short/truncated stream is rejected as unsupported rather than compared against unread buffer contents. This makes the accept decision depend only on bytes that were actually read from the upload, closing the gap the scanner flagged at the `Read` call while preserving the existing storage behavior: random GUID filename, server-assigned extension, and a `private-uploads` directory outside any static-file root.
