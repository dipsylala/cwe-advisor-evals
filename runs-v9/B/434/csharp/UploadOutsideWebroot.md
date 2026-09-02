## Verdict

Exploitable. Confidence: high.

## Source

- **Source**: the `file` parameter (`IFormFile`) bound from the multipart body of `POST /upload`. Both `file.FileName` and the byte content are fully client-controlled; nothing upstream constrains them.
- **Sink**: `Path.Combine(uploadRoot, file.FileName)` (line 28) builds the on-disk destination directly from the client-supplied name, and `System.IO.File.Create(destination)` / `file.CopyToAsync(stream)` (lines 30-31) write the client's raw bytes there under that name and extension.
- **Trace**: `file` -> `file.FileName` -> `destination` -> `File.Create(destination)`. No step between source and sink inspects the file's content, extension, or `ContentType`, and no allowlist of permitted types exists anywhere in the method. Storage does land under `_env.ContentRootPath` rather than under `wwwroot`, so it is outside the static-file root the framework serves directly - that part of the language guidance's defense-in-depth is already satisfied and the fix below does not need to change it. The live gap is the missing type check plus using the attacker-chosen name and extension verbatim for storage, which is exactly the CWE-434 pattern: any file type, including one that is dangerous if later served, executed via runtime compilation, or picked up by another component scanning that content-root path, is accepted and persisted with the extension the client chose.

## Fix

Vulnerable code (`UploadOutsideWebrootController.Upload`, lines 24-33):

```csharp
var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
Directory.CreateDirectory(uploadRoot);

// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
var destination = Path.Combine(uploadRoot, file.FileName);

await using var stream = System.IO.File.Create(destination);
await file.CopyToAsync(stream);

return Ok(new { stored = Path.GetFileName(destination), bytes = file.Length });
```

Fixed code:

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases;

[ApiController]
public class UploadOutsideWebrootController : ControllerBase
{
    private readonly IWebHostEnvironment _env;

    // Business-required types only, matched by leading file signature (magic bytes).
    private static readonly IReadOnlyList<(string Extension, byte[] Signature)> AllowedSignatures = new[]
    {
        (".png", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }),
        (".jpg", new byte[] { 0xFF, 0xD8, 0xFF }),
        (".pdf", new byte[] { 0x25, 0x50, 0x44, 0x46 }),
    };

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

        await using var uploadStream = file.OpenReadStream();

        var header = new byte[8];
        var bytesRead = await uploadStream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false);
        uploadStream.Seek(0, SeekOrigin.Begin);

        var matched = AllowedSignatures.FirstOrDefault(candidate =>
            bytesRead >= candidate.Signature.Length &&
            header.AsSpan(0, candidate.Signature.Length).SequenceEqual(candidate.Signature));

        if (matched.Extension is null)
        {
            return BadRequest("Unsupported file type.");
        }

        var storedFileName = Guid.NewGuid().ToString("N") + matched.Extension;
        var destination = Path.Combine(uploadRoot, storedFileName);

        await using var stream = new FileStream(destination, FileMode.CreateNew);
        await uploadStream.CopyToAsync(stream);

        return Ok(new { stored = storedFileName, bytes = file.Length });
    }
}
```

## Explanation

The fix replaces the missing type check with content-based validation: it reads the leading bytes of the upload directly from `file.OpenReadStream()` via `ReadAtLeastAsync` (so a short read can't leave zeroed bytes compared against a real signature), rewinds the stream, and compares them against an allowlist of magic-number signatures for the business-required types (PNG/JPEG/PDF are illustrative; the real allowlist should match what the endpoint is meant to accept). A file whose content doesn't match a known signature is rejected with 400 before anything is written. On a match, the storage filename is generated with `Guid.NewGuid().ToString("N")` and the extension is taken from the matched allowlist entry - never from `file.FileName` - which also closes the secondary path-traversal exposure of using a client-supplied name as part of the disk path. The destination is opened with `FileMode.CreateNew` so a name collision fails loudly instead of silently overwriting another file, consistent with the language guidance's break-taint-after-validation pattern. Storage already lived under `_env.ContentRootPath`, outside `wwwroot`/`UseStaticFiles()`, so that control was left as-is.

## Behaviour changes

- The response's `stored` field now returns the generated GUID-based filename instead of the client-supplied `file.FileName`; callers that echoed or relied on the original filename in the response will see a different value. This is required by the fix - the client-supplied name can no longer be used as the storage identity.
- Uploads whose content doesn't match an allowed signature now receive `400 Bad Request` instead of being stored; any previously-accepted file type outside the allowlist is now rejected. This is the intended effect of the fix and the reason the finding is closed.
- The destination file is now opened with `FileMode.CreateNew` instead of the default overwrite behavior of `File.Create`; a collision now throws `IOException` rather than silently overwriting an existing file. With a GUID-derived name this is expected to be effectively unreachable in practice, and is the safer failure mode called for by the language guidance.
- Not changed: overall request/response shape (still `Ok(new { stored, bytes })` on success), the storage root (`_env.ContentRootPath/storage/uploads`, already outside `wwwroot`), and no request size limit was added - that is a separate, secondary hardening control (`FormOptions.MultipartBodyLengthLimit`) not required to close this specific finding and left out to keep the change scoped to the reported sink.
