## Verdict

- **CWE**: CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **Location**: `UploadOutsideWebroot.cs`, line 28 (`Path.Combine(uploadRoot, file.FileName)`), feeding the write at line 30 (`System.IO.File.Create(destination)`)
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Source**: the `file` parameter (`IFormFile`) of `Upload`, model-bound from the multipart/form-data body of `POST /upload`. Both `file.FileName` and the byte content of the upload are attacker-controlled.
- **Sink**: line 28 builds the on-disk destination path by combining the upload directory with the raw, client-supplied `file.FileName`; line 30 creates that file and line 31 copies the full request body into it.
- **Trace**: nothing between source and sink inspects the file's type or content. `file.FileName` is used verbatim as the storage filename (permitting arbitrary/traversal-bearing names), and there is no signature, extension, or Content-Type allowlist check anywhere in the method - so a script, HTML/SVG document, or any other dangerous type is written to disk unmodified with a name the client chose. The write already lands under `_env.ContentRootPath` (outside `wwwroot`), so directory placement is not the defect; the missing type validation and the use of the client-supplied filename as the storage path are.

## Fix

### File: UploadOutsideWebroot.cs

```csharp
using System;
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

    // Allowlist of accepted file types, matched by leading signature (magic) bytes read from
    // the actual upload stream - never from the client-supplied filename or Content-Type.
    private static readonly (byte[] Signature, string Extension)[] AllowedSignatures =
    {
        (new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, ".png"),
        (new byte[] { 0xFF, 0xD8, 0xFF }, ".jpg"),
        (new byte[] { 0x47, 0x49, 0x46, 0x38 }, ".gif"),
        (new byte[] { 0x25, 0x50, 0x44, 0x46 }, ".pdf"),
    };

    public UploadOutsideWebrootController(IWebHostEnvironment env) => _env = env;

    [HttpPost("/upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest();
        }

        var headerLength = AllowedSignatures.Max(s => s.Signature.Length);
        var header = new byte[headerLength];

        await using (var inspectStream = file.OpenReadStream())
        {
            var bytesRead = await inspectStream.ReadAtLeastAsync(header, headerLength, throwOnEndOfStream: false);
            if (bytesRead < headerLength)
            {
                Array.Resize(ref header, bytesRead);
            }
        }

        var matchedExtension = AllowedSignatures
            .Where(s => header.Length >= s.Signature.Length && header.AsSpan(0, s.Signature.Length).SequenceEqual(s.Signature))
            .Select(s => s.Extension)
            .FirstOrDefault();

        if (matchedExtension is null)
        {
            return BadRequest("Unsupported file type.");
        }

        var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
        Directory.CreateDirectory(uploadRoot);

        // Storage path is a server-generated name, never the client-supplied FileName.
        var storedFileName = Guid.NewGuid().ToString("N") + matchedExtension;
        var destination = Path.Combine(uploadRoot, storedFileName);

        await using var stream = new FileStream(destination, FileMode.CreateNew);
        await file.CopyToAsync(stream);

        return Ok(new { stored = Path.GetFileName(destination), bytes = file.Length });
    }
}
```

## Explanation

The original code trusted the request in two ways that combine into CWE-434: it never checked what kind of file was being uploaded, and it wrote the file under a name the client chose (`file.FileName`), which also carries path-traversal risk into the destination path. The fix reads the first bytes of the actual upload stream via `IFormFile.OpenReadStream()` and matches them against an allowlist of known file signatures (PNG, JPEG, GIF, PDF magic numbers), using `ReadAtLeastAsync` so a short read can't be mistaken for a mismatched signature. Only a file whose real content matches an allowed signature proceeds; everything else is rejected with 400 before anything is written to disk. The matched allowlist entry - not the client-supplied name or extension - then determines the extension used for storage, and the file is saved under a freshly generated `Guid.NewGuid().ToString("N")` name via `FileMode.CreateNew`, so the client-controlled `FileName` never reaches the filesystem path and cannot be used for traversal, overwrite, or to smuggle a dangerous extension through. The directory itself was already outside `wwwroot`, so that part of the original code is unchanged.

## Behaviour changes

- **Uploads are now type-restricted**: files that previously would have been accepted unconditionally are rejected (400 `"Unsupported file type."`) unless their content matches one of the allowlisted signatures. This is the intended effect of the fix, not a side effect - the allowlist (PNG/JPEG/GIF/PDF) is an assumed placeholder for this generic endpoint; it should be replaced with the caller's actual business-required file types before deployment.
- **Stored filename changed**: the response's `stored` field and the on-disk file name are now a generated GUID plus the detected extension, instead of the client-supplied `file.FileName`. Any caller that depended on the original filename being preserved will see a different value; this is required to remove path-traversal and dangerous-extension control from the client.
- **Write failure mode changed**: storage now uses `new FileStream(destination, FileMode.CreateNew)` instead of `System.IO.File.Create` (which silently overwrites). `CreateNew` throws `IOException` if the generated name already exists. With a fresh GUID per request this is a negligible-probability case, but unlike the original it is no longer silently overwritten; there is no explicit catch for it here, so a collision would surface as an unhandled exception (500). This follows the loaded guidance's recommended write mode.
- **The upload stream is opened twice**: once via `OpenReadStream()` to read the header for signature checking, and again implicitly inside `file.CopyToAsync()`. ASP.NET Core's model binder has already buffered the multipart upload (in memory or to a temp file) before the action runs, so this does not re-read the network request and the full file content is still copied to storage.
- **Not changed / not in scope**: request size limits (`FormOptions.MultipartBodyLengthLimit` / `[RequestSizeLimit]`), authentication/authorization on the endpoint, and image re-encoding to strip active content are all defence-in-depth items the loaded guidance also recommends, but they are separate controls from the sink at line 28 and were left out to keep the fix scoped to the reported finding.
- **Verification**: the fixed file was compiled with `dotnet build` in a scratch ASP.NET Core project (`Microsoft.NET.Sdk.Web`, `net9.0`, referencing `Microsoft.AspNetCore.App`) containing only this controller and a minimal `Program.cs`. Build succeeded with 0 warnings and 0 errors, confirming `Stream.ReadAtLeastAsync`, `FileMode.CreateNew`, `IFormFile.OpenReadStream`, and the rest of the API surface used all resolve correctly against the framework.
- **Assumptions**: the concrete allowed file types (PNG/JPEG/GIF/PDF) are not given by the finding, so a representative image/document allowlist was assumed for this generic endpoint; the calling team should substitute their actual accepted types and corresponding signatures.
