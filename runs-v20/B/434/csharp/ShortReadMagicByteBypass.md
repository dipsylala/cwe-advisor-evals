## Verdict

Exploitable. CWE-434 (Unrestricted Upload of File with Dangerous Type), C#/ASP.NET Core.

## Source

`IFormFile file` bound from the multipart body of `POST api/document-upload/attachments` (`DocumentUploadController.UploadAttachment`). The file's byte stream, obtained via `file.OpenReadStream()`, is fully attacker-controlled.

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
            // A single Read() may return fewer bytes than requested; ReadAtLeastAsync loops
            // internally until the header is fully populated (or the stream ends), so the
            // signature comparison below never runs against zero-filled bytes that were
            // never actually read from the file.
            int bytesRead = await stream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false);

            if (bytesRead < header.Length)
            {
                return BadRequest("Unsupported file type.");
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

`Stream.Read(buffer, offset, count)` is only contractually required to return at least one byte (short of end-of-stream); it is not required to fill the buffer, and the stream backing an `IFormFile` is fed from the network in chunks, so a short first read is a routine occurrence, not an edge case an attacker even needs to force. When that happens, the unread tail of `header` keeps its default zero value, and the code went on to run the signature comparison over the full 8/5-byte span regardless of how many bytes had actually arrived from the file - `bytesRead` was captured but never checked. Any file whose true bytes don't independently reproduce the zeroed tail fails validation, so the immediate effect is that legitimate PNG/PDF uploads are intermittently rejected depending on network chunking, and the check's outcome stops being a reliable statement about the file's real content, which is the mechanism CWE-434 flags: a type gate that can pass or fail based on something other than the file's actual bytes cannot be trusted to keep dangerous types out. The fix replaces the single `Read` call with `Stream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false)` (added in .NET 7), which loops internally until it has obtained the full 8 bytes or the stream ends, and returns the number of bytes actually obtained without throwing on a short stream. An explicit `bytesRead < header.Length` check follows and rejects with the same "Unsupported file type" response used for a genuine signature mismatch, so a file too short to carry a full header - which can never be a valid PNG and can be a valid PDF only in a truncated, unusable form - is turned away instead of being compared against bytes it never contained. Every subsequent step (span-based signature comparison, seek-back, allowlist-derived extension, storage under a generated name outside the content root) is unchanged and still runs only after `header` is confirmed to hold 8 genuine bytes from the file.

## Behaviour changes

- The single `stream.Read(header, 0, header.Length)` call is replaced with `await stream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false)`. Reason: closes the weakness - guarantees `header` holds real file bytes for its full length (or the read stops at true end-of-stream) before any signature comparison runs, instead of silently accepting whatever a single chunked read happened to deliver.
- New early-exit branch: `if (bytesRead < header.Length) return BadRequest("Unsupported file type.")`. Reason: a file shorter than 8 bytes cannot be a valid PNG and can be a valid PDF only in a degenerate, unusable form, so it is rejected the same way a signature mismatch already is; without this branch the fixed `bytesRead` value would be usable but never checked, leaving the same gap the fix closes.
- The endpoint's public signature, response shape (`storedName`, `bytesRead`, `length`), status codes returned, allowlisted extension mapping, storage location, and stream rewind/copy logic are all unchanged.

None of these differences alter what the endpoint returns to a caller uploading a genuine, fully-transmitted PNG or PDF of at least 8 bytes; the only new outcome is that a truncated or too-short upload now reliably gets the existing "Unsupported file type" rejection instead of a result that depended on network chunking.

## Verification

Compiled the fixed file (as `ShortReadMagicByteBypass.cs` under `Controllers/`) into a scratch ASP.NET Core Web API project targeting the installed .NET 10 SDK (`dotnet build`), confirming `Stream.ReadAtLeastAsync` resolves and the file builds with 0 errors (2 pre-existing template warnings, both an unrelated `Microsoft.OpenApi` package advisory, not from this file). Manually re-checked every caller of `bytesRead` and `header` after the change - the `Ok(new { storedName, bytesRead, length = file.Length })` response and the `AsSpan` signature comparisons are unaffected since `bytesRead` is now guaranteed to equal `header.Length` (8) whenever execution reaches them. `ReadAtLeastAsync` and its `throwOnEndOfStream` parameter come from the loaded C# guidance (`cwe/434/csharp/INDEX.md`), which names this exact API for this exact bug.

## Assumptions

None - the loaded guidance names both the defect (a single `Read` leaving a zero-padded tail compared as if it were file content) and the exact fix (`ReadAtLeastAsync` / loop until the header is filled) for this scenario.
