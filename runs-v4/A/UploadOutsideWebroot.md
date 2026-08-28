## Verdict

True positive. The `/upload` action accepts any `IFormFile` and writes it to disk with no check on the file's type or content, and it builds the destination path directly from the client-supplied `file.FileName`. Both halves of CWE-434 are present.

The one mitigation already in place is the storage location: `Path.Combine(_env.ContentRootPath, "storage", "uploads")` is outside `wwwroot`, so an upload that lands where intended is not served by `UseStaticFiles`. That does not close the finding, for two reasons:

- Nothing constrains where the file actually lands. `Path.Combine` does not sanitise its second argument: a `FileName` of `..\..\wwwroot\payload.html` escapes the upload directory, and a rooted `FileName` such as `C:\inetpub\wwwroot\shell.cshtml` causes `Path.Combine` to discard `uploadRoot` entirely and return the client's path verbatim. ASP.NET Core does not sanitise `IFormFile.FileName` - it is the raw `filename` parameter from the multipart `Content-Disposition` header.
- Writes outside `wwwroot` are not automatically harmless. A `.cshtml` dropped into the views tree of an app using `AddRazorRuntimeCompilation()` is compiled and executed on the next request, and an assembly written where a plugin loader will find it behaves the same way. An `.html` or `.svg` steered back under `wwwroot` is served from the application's own origin and runs script against the user's session.

Secondary defects on the same statement group: `File.Create` uses `FileMode.Create`, which silently overwrites an existing file of the same name, and the action enforces no upload size limit.

## Source

Taint path, single file, no intermediate hops:

- **Source** - `IFormFile file`, the model-bound multipart upload on `Upload` (line 17). Attacker-controlled in full: the byte content, the `Content-Type`, and the `filename` parameter of the `Content-Disposition` header that becomes `file.FileName`.
- **Propagation** - `file.FileName` is passed unvalidated as the second argument to `Path.Combine` on line 28, producing `destination`.
- **Sink** - `System.IO.File.Create(destination)` on line 30, followed by `file.CopyToAsync(stream)` on line 31, which writes the attacker's bytes to the attacker-influenced path.

No validation exists anywhere along that path. The `file.Length == 0` test is a liveness check, not a type, size, or path check.

```csharp
var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
Directory.CreateDirectory(uploadRoot);

// Client-supplied FileName used as the storage path: traversal or a rooted path
// escapes uploadRoot, and nothing constrains the file's type or content.
var destination = Path.Combine(uploadRoot, file.FileName);

await using var stream = System.IO.File.Create(destination);
await file.CopyToAsync(stream);
```

Sink contract the fix has to satisfy:

- **Returns** - a path string consumed by `File.Create`, then reduced to its leaf by `Path.GetFileName` for the JSON response.
- **Discards** - the full path never reaches the client; only the leaf name and the byte count do. The fix keeps it that way.
- **Implicit arguments** - `File.Create(path)` defaults to `FileMode.Create` (truncate or overwrite), `FileAccess.ReadWrite`, `FileShare.None`. The overwrite default is security-relevant and is replaced deliberately.
- **Failure behaviour** - I/O errors propagate as unhandled exceptions and surface as a 500; the only handled rejection is the `BadRequest()` for a missing or empty file. The fix rejects through that same path and adds no new exception handling.

## Fix

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases;

[ApiController]
public class UploadOutsideWebrootController : ControllerBase
{
    private const long MaxUploadBytes = 4 * 1024 * 1024;

    // Signature allowlist. The stored extension is chosen here from the detected
    // type, never taken from the client's filename or Content-Type.
    private static readonly (byte[] Signature, string Extension)[] AllowedTypes =
    {
        (new byte[] { 0xFF, 0xD8, 0xFF }, ".jpg"),
        (new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, ".png"),
        (new byte[] { 0x25, 0x50, 0x44, 0x46, 0x2D }, ".pdf"),
    };

    private readonly IWebHostEnvironment _env;

    public UploadOutsideWebrootController(IWebHostEnvironment env) => _env = env;

    [HttpPost("/upload")]
    [RequestSizeLimit(MaxUploadBytes)]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0 || file.Length > MaxUploadBytes)
        {
            return BadRequest();
        }

        var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
        Directory.CreateDirectory(uploadRoot);

        await using var upload = file.OpenReadStream();

        // A single Read can return fewer bytes than asked for, which would leave the
        // tail of the buffer zeroed and compare against bytes never in the file.
        var header = new byte[8];
        var headerLength = await upload.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false);

        var extension = MatchAllowedType(header.AsSpan(0, headerLength));
        if (extension is null)
        {
            return BadRequest();
        }

        // Server-generated name: no part of file.FileName reaches the path, so
        // traversal sequences and rooted paths have nothing to act on.
        var storedName = Guid.NewGuid().ToString("N") + extension;
        var destination = Path.Combine(uploadRoot, storedName);

        upload.Seek(0, SeekOrigin.Begin);

        await using var stream = System.IO.File.Open(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await upload.CopyToAsync(stream);

        return Ok(new { stored = storedName, bytes = file.Length });
    }

    private static string? MatchAllowedType(ReadOnlySpan<byte> header)
    {
        foreach (var (signature, extension) in AllowedTypes)
        {
            if (header.Length >= signature.Length && header[..signature.Length].SequenceEqual(signature))
            {
                return extension;
            }
        }

        return null;
    }
}
```

Trim `AllowedTypes` to the formats this endpoint actually needs - the allowlist should express the business requirement, not a generous default.

No library change is required. If the endpoint accepts images, add a decode-and-re-save pass (for example with `SixLabors.ImageSharp`) before persisting; take its version from advisory or SCA data rather than from recall, and confirm the resolved version with dependency-check tooling before merging.

## Explanation

The fix breaks the two links the finding depends on. First, it establishes the file's type from the bytes themselves: the stream is opened with `OpenReadStream()`, the leading bytes are filled with `ReadAtLeastAsync`, and that header is matched against a signature allowlist. `ReadAtLeastAsync` rather than a single `Read` matters here, because a short read leaves the rest of the buffer zeroed and the comparison is then made against bytes that were never in the file. `IFormFile.ContentType` and the extension of `IFormFile.FileName` are ignored throughout, since both are request metadata the client writes and the framework does not verify.

Second, it breaks taint at the allowlist rather than merely gating on it. The value that flows onward is the `extension` selected from the matched allowlist entry, joined to a `Guid.NewGuid().ToString("N")` value, so the storage path is composed entirely of server-controlled data. With `file.FileName` no longer reaching `Path.Combine`, the traversal and rooted-path cases collapse and the write is confined to `uploadRoot`, which already sits outside `wwwroot`. Deriving the extension from the detected type rather than carrying over the client's suffix is the point of that step: the extension decides how the file is served later, so a randomised name that keeps the client's suffix still concedes the half that matters. `Guid.NewGuid().ToString("N")` is preferred to `Path.GetRandomFileName()`, which returns an 8.3-style name that already contains a dot and would produce a double-extension filename once a suffix is appended.

Everything else that differs from the original traces to the same weakness. `FileMode.CreateNew` replaces the overwrite default of `File.Create` so one upload cannot displace an existing stored file, and `FileAccess.Write` matches what the code actually does. The size bound - the `[RequestSizeLimit]` attribute, which applies before the body is fully buffered, plus the `file.Length` guard - is the resource-exhaustion control this weakness class calls for, and it rejects through the existing `BadRequest()` path rather than introducing new failure modes. `upload.Seek(0, SeekOrigin.Begin)` rewinds after the header read so the whole file is written, and the copy now runs from `upload` rather than `file` because the validated stream is the one that must be persisted; copying from `file` again would write a stream that was never inspected. The response keeps its shape and still discloses only the leaf name and the byte count, but `stored` is now the generated name instead of the client's. That is an unavoidable consequence of not storing under the client's filename, and it is the value a caller needs in order to reference the file later; if anything elsewhere looks files up by their original name, it needs a stored-name-to-display-name mapping in the database.

One limit is worth stating plainly: a signature check is a filter, not proof. It identifies the prefix only, so a polyglot carrying a valid header followed by script passes every signature test ever written. Where uploads are images, re-encoding through decode-and-re-save is what actually strips such a payload. Keep the upload directory out of `UseStaticFiles()`, and serve files back through an authorised action that sets the content type along with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, rather than exposing the directory.

To verify: re-run the scanner, then confirm that a `.jpg` whose content is HTML is rejected, that a `FileName` of `..\..\wwwroot\x.html` and a rooted `FileName` both land inside `uploadRoot` under a generated name, that an oversized upload is rejected, and that a normal upload of an allowed type still round-trips.
