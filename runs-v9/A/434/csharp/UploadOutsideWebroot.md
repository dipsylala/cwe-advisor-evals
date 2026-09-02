## Verdict

Confirmed. The endpoint accepts any uploaded file and writes it to disk using the client-supplied `file.FileName` with no extension allowlist, no content-type/signature check, and no filename sanitization. Storing under `ContentRootPath` keeps the file out of the static-file webroot, but that alone does not stop a dangerous file type from being uploaded and later executed, moved, or served by another code path (e.g. a download/admin endpoint, a scheduled job, or a future change that serves from this directory). The raw `file.FileName` is also attacker-controlled and is used directly in `Path.Combine`, which is a path-traversal / overwrite risk on top of the CWE-434 finding.

## Source

`file` (the `IFormFile` bound from the multipart request body in `Upload(IFormFile file)`), specifically `file.FileName` and `file.CopyToAsync`/`file`'s content stream — both fully attacker-controlled.

## Fix

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

    // Allowlist of extensions this endpoint accepts. Adjust to the real business need;
    // never include executable/script/interpreted types (.exe, .dll, .sh, .php, .js, .html, ...).
    private static readonly string[] AllowedExtensions = { ".png", ".jpg", ".jpeg", ".pdf" };

    // Magic-byte signatures for the same allowlist, so a renamed file is still rejected.
    private static readonly (string Ext, byte[] Signature)[] Signatures =
    {
        (".png", new byte[] { 0x89, 0x50, 0x4E, 0x47 }),
        (".jpg", new byte[] { 0xFF, 0xD8, 0xFF }),
        (".jpeg", new byte[] { 0xFF, 0xD8, 0xFF }),
        (".pdf", new byte[] { 0x25, 0x50, 0x44, 0x46 }),
    };

    private const long MaxFileSizeBytes = 10 * 1024 * 1024; // 10 MB

    public UploadOutsideWebrootController(IWebHostEnvironment env) => _env = env;

    [HttpPost("/upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest();
        }

        if (file.Length > MaxFileSizeBytes)
        {
            return BadRequest("File exceeds the maximum allowed size.");
        }

        // Validate extension against an allowlist. Do not trust or use the client-supplied
        // file name for storage; only its extension is consulted, and only after normalizing.
        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (!AllowedExtensions.Contains(extension))
        {
            return BadRequest("File type not permitted.");
        }

        // Confirm the content actually matches the claimed extension (magic-byte check),
        // so a script/executable renamed with an allowed extension is still rejected.
        if (!await MatchesSignatureAsync(file, extension))
        {
            return BadRequest("File content does not match the declared file type.");
        }

        var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
        Directory.CreateDirectory(uploadRoot);

        // Generate the stored file name server-side; never derive it from client input.
        // This removes the path-traversal/overwrite risk and any dangerous name/extension trick.
        var storedFileName = $"{Guid.NewGuid():N}{extension}";
        var destination = Path.Combine(uploadRoot, storedFileName);

        await using (var stream = System.IO.File.Create(destination))
        {
            await file.CopyToAsync(stream);
        }

        return Ok(new { stored = storedFileName, bytes = file.Length });
    }

    private static async Task<bool> MatchesSignatureAsync(IFormFile file, string extension)
    {
        var candidates = Signatures.Where(s => s.Ext == extension).ToArray();
        if (candidates.Length == 0)
        {
            return false;
        }

        var headerLength = candidates.Max(s => s.Signature.Length);
        var header = new byte[headerLength];

        await using var stream = file.OpenReadStream();
        var read = await stream.ReadAsync(header.AsMemory(0, headerLength));

        return candidates.Any(s =>
            read >= s.Signature.Length &&
            header.Take(s.Signature.Length).SequenceEqual(s.Signature));
    }
}
```

## Explanation

Three changes close the finding:

1. **Extension allowlist** (`AllowedExtensions`) rejects any file type the application does not intend to accept, instead of accepting anything and relying on storage location alone to neutralize danger.
2. **Magic-byte verification** (`MatchesSignatureAsync`) confirms the uploaded bytes actually match the claimed type, so an attacker cannot bypass the extension check by simply renaming an executable or script (e.g. `shell.php.png`) to an allowed extension.
3. **Server-generated storage name** (`Guid.NewGuid():N` + validated extension) replaces the client-supplied `file.FileName` entirely, so the stored path can never be influenced by attacker input — eliminating both the path-traversal/overwrite risk and any trick relying on a crafted file name (double extensions, null bytes, reserved device names, etc.).

Storing outside the webroot (`ContentRootPath`, not `WebRootPath`) is retained and is good defense-in-depth against direct execution via the static file middleware, but it is not sufficient on its own: it does nothing to prevent a dangerous file from being accepted in the first place, and any future code path that reads from `storage/uploads` (an admin download endpoint, an image-processing job, a virus-scan worker that shells out to the file, etc.) would still be exposed to whatever was uploaded. A file-size limit was also added since the original handler only rejected empty uploads.

If the deployment can host a dedicated antivirus/content-scanning service, route the saved file through it before it is considered available to other parts of the system, and keep the extension allowlist and magic-byte check as the first-line defense regardless.
