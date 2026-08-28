## Verdict

- **CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **Location:** `e:/Github/cwe-advisor/evals/cases/434/csharp/UploadOutsideWebroot/UploadOutsideWebroot.cs`, line 28 (path built), line 30 (file written)
- **Verdict:** `exploitable`
- **Confidence:** high for the weakness and the trace; medium for the concrete allowlist, which had to be chosen without knowing the endpoint's business file types (see Behaviour changes).

The endpoint accepts an `IFormFile` and writes it to disk with no check of the file's type or content, and with the client-supplied filename used as the storage name. Two distinct defects are live at the sink:

1. **No type allowlist at all.** Any content is accepted and persisted, including HTML/SVG carrying script, Razor views, or native executables. Neither the signature, the extension, nor `ContentType` is inspected.
2. **Client-controlled storage path.** `IFormFile.FileName` comes from the `Content-Disposition` header of the multipart body. ASP.NET Core does not sanitise it, and `Path.Combine` gives the attacker two escapes from `storage/uploads`: traversal segments (`..\..\Views\Shared\_Layout.cshtml`) and, more directly, a rooted value (`C:\inetpub\...` or `/var/www/...`), which makes `Path.Combine` discard `uploadRoot` entirely and return the attacker's path verbatim.

Storing outside `wwwroot` reduces but does not remove the impact. It stops the direct "fetch back the uploaded file from the app's own origin" case, which is where stored XSS from an uploaded `.html` or `.svg` lives. It does not stop the write itself from landing somewhere dangerous inside the content root: a `.cshtml` dropped into the views tree of an app using `AddRazorRuntimeCompilation()` is compiled and executed on the next request, a written assembly is executed by any plugin/probing loader, and configuration or data files can be overwritten because `File.Create` truncates an existing file. That is why the traversal half of this finding matters even though the intended directory is already outside the webroot.

## Source

**Data flow**

- **Source:** the `file` parameter of `Upload` (line 17), model-bound from the multipart request body. Both `file.FileName` and the file bytes are attacker-controlled.
- **Propagation:** `file.FileName` -> `Path.Combine(uploadRoot, file.FileName)` (line 28) -> `destination`.
- **Sink:** `System.IO.File.Create(destination)` (line 30) followed by `file.CopyToAsync(stream)` (line 31) - attacker-chosen bytes written to an attacker-influenced path under an attacker-chosen extension.
- **Guards between source and sink:** only `file is null || file.Length == 0` (line 19). It constrains neither the path nor the content, so nothing on the path is broken.

**Existing sink contract** (what the fix has to preserve)

- **Returns:** `File.Create` returns a writable `FileStream` consumed by `CopyToAsync`; `destination` is also read back by `Path.GetFileName(destination)` for the `stored` field of the 200 response.
- **Discards:** nothing - the response already exposes only the leaf name and the byte count.
- **Implicit arguments:** `File.Create(path)` is `FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, 4096)`. `FileMode.Create` silently truncates an existing file. `Path.Combine` silently drops its first argument when the second is rooted.
- **Failure behaviour:** rejects with `400` for null/empty input; otherwise unhandled `IOException` / `UnauthorizedAccessException` from `File.Create` and `CopyToAsync` propagate and surface as `500`.

**Vulnerable code**

```csharp
    [HttpPost("/upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest();
        }

        var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
        Directory.CreateDirectory(uploadRoot);

        // VULNERABLE: file.FileName is the client's Content-Disposition value. It is never validated,
        // so it can traverse out of uploadRoot or be rooted (Path.Combine then discards uploadRoot),
        // and it carries an attacker-chosen extension.
        var destination = Path.Combine(uploadRoot, file.FileName);

        // VULNERABLE: the bytes are never inspected, so any dangerous type is accepted, and
        // FileMode.Create (File.Create's default) truncates whatever is already at that path.
        await using var stream = System.IO.File.Create(destination);
        await file.CopyToAsync(stream);

        return Ok(new { stored = Path.GetFileName(destination), bytes = file.Length });
    }
```

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
    private const int MaxUploadBytes = 10 * 1024 * 1024;
    private const int SignatureLength = 8;

    // Allowlist of permitted types: leading bytes -> the extension the file is stored under.
    // The stored extension is derived from the detected type, never from the request.
    private static readonly (byte[] Signature, string Extension)[] AllowedTypes =
    {
        (new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, ".png"),
        (new byte[] { 0xFF, 0xD8, 0xFF }, ".jpg"),
        (new byte[] { 0x25, 0x50, 0x44, 0x46, 0x2D }, ".pdf"),
    };

    private readonly IWebHostEnvironment _env;

    public UploadOutsideWebrootController(IWebHostEnvironment env) => _env = env;

    [HttpPost("/upload")]
    [RequestSizeLimit(MaxUploadBytes)]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest();
        }

        var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
        Directory.CreateDirectory(uploadRoot);

        // Identify the type from the file's own bytes, not from FileName or ContentType.
        // ReadAtLeastAsync fills the header buffer; a single Read may return fewer bytes and
        // leave the tail zeroed, which would compare against bytes never present in the file.
        var header = new byte[SignatureLength];
        int headerLength;
        await using (var probe = file.OpenReadStream())
        {
            headerLength = await probe.ReadAtLeastAsync(header, SignatureLength, throwOnEndOfStream: false);
        }

        var extension = MatchAllowedType(header, headerLength);
        if (extension is null)
        {
            return BadRequest();
        }

        // Both halves of the storage name are server-controlled: a random stem and the
        // extension taken from the allowlist entry that matched. file.FileName is not used.
        var destination = Path.Combine(uploadRoot, Guid.NewGuid().ToString("N") + extension);

        await using var stream = System.IO.File.Open(destination, FileMode.CreateNew);
        await file.CopyToAsync(stream);

        return Ok(new { stored = Path.GetFileName(destination), bytes = file.Length });
    }

    private static string? MatchAllowedType(byte[] header, int headerLength)
    {
        foreach (var (signature, extension) in AllowedTypes)
        {
            if (headerLength >= signature.Length &&
                header.AsSpan(0, signature.Length).SequenceEqual(signature))
            {
                return extension;
            }
        }

        return null;
    }
}
```

**Dependency note.** No library is required for the fix above. A signature check identifies the file's prefix only, so a polyglot that begins with a valid PNG or JPEG header and continues with script still passes it. If these files are ever served back to a browser, decode and re-save each image through a maintained imaging library - `SixLabors.ImageSharp` is the usual choice for ASP.NET Core - so the stored bytes are the re-encoded output rather than the uploaded bytes. Take the version from advisory or SCA data rather than pinning one by hand, and confirm the resolved version with dependency-check tooling before merging.

**Also worth confirming at configuration level:** `FormOptions.MultipartBodyLengthLimit`, so an oversized body is rejected before it is fully buffered, and that `storage/uploads` is not exposed by `UseStaticFiles()`.

## Explanation

The fix removes every attacker-controlled component from the storage path and adds the type check the endpoint never had. `file.FileName` is no longer read at all, so traversal segments and rooted paths have nothing to act on - the destination is now `uploadRoot` plus a `Guid.NewGuid().ToString("N")` stem, which cannot contain a separator, a drive prefix, or a dot. The extension, which is the part that decides how the file is later treated and served, comes from the allowlist entry matched against the file's own leading bytes rather than from the request, so the client can no longer choose it even indirectly; `IFormFile.ContentType` is deliberately not consulted, because like `FileName` it is unverified request metadata. Content that matches no allowlist entry is rejected with `400` before anything is written, which is what closes the "dangerous type" half of the finding, and `FileMode.CreateNew` replaces `File.Create`'s truncating `FileMode.Create` so a write can no longer overwrite an existing file. The remaining sink contract is unchanged: the same `FileStream` is copied into by the same `CopyToAsync`, the response still returns the stored leaf name and byte count, and the null/empty guard and its `400` are untouched.

## Behaviour changes

Differences between the original and the fixed code, each with its reason:

- **`file.FileName` is no longer used for the storage path; the name is `Guid.NewGuid().ToString("N")` plus the allowlist-derived extension.** This is the fix for the path half of the weakness. Consequence for callers: the `stored` value in the response is now a server-generated name, not the client's filename, and the original filename is no longer persisted anywhere. If the application needs to display the uploaded name later, store it as metadata (for example a database column) alongside the generated name, and do not use it to build any filesystem path. `Path.GetRandomFileName()` is deliberately not used here - it returns an 8.3-style name that already contains a dot, so appending an extension produces a double-extension name.
- **Uploads whose leading bytes match no allowlist entry are rejected with `400` instead of being stored.** This is the fix for the dangerous-type half. Previously every upload succeeded; now PNG, JPEG and PDF succeed and everything else - including files shorter than the signature being compared - returns `400`. Adjust `AllowedTypes` to the endpoint's real business types before applying.
- **The file's first bytes are read once through an extra `file.OpenReadStream()` before the copy.** Needed to identify the type from content. The probe stream is scoped and disposed on its own, so `file.CopyToAsync` still writes the complete file from position zero and line-for-line keeps its original form; disposing the reference stream does not dispose the underlying buffered request body. (Reading the header from a single stream and rewinding with `Seek(0, SeekOrigin.Begin)` is the equivalent alternative; the separate probe avoids depending on that stream being seekable.)
- **`System.IO.File.Create(destination)` becomes `System.IO.File.Open(destination, FileMode.CreateNew)`.** `File.Create` implies `FileMode.Create`, which truncates an existing file - part of the impact of the original defect. The two-argument `File.Open` overload keeps `File.Create`'s other implicit arguments (`FileAccess.ReadWrite`, `FileShare.None`) and changes only the mode. New failure mode: an `IOException` if the path already exists. With a GUID stem that is effectively unreachable, and it is the correct outcome rather than a silent overwrite; it propagates as a `500` exactly as the original's `IOException` did.
- **`[RequestSizeLimit(MaxUploadBytes)]` added (10 MB).** Size bounding is a secondary control for this weakness. Requests above the limit now fail with `413` where they previously succeeded. Set the constant to the endpoint's real limit - the 10 MB value is a placeholder, not a derived requirement.
- **Everything else is unchanged:** the route, signature, `IWebHostEnvironment` injection, the `uploadRoot` computation, `Directory.CreateDirectory`, the null/empty guard and its `400`, and the shape of the 200 response.

**Assumptions resolved without asking (autonomous run):**

- The endpoint's permitted file types are not stated in the case, and only one file was available for review. PNG, JPEG and PDF were assumed as a representative document/image allowlist. This is the one part of the fix a reviewer must retune; an application accepting, say, ZIP or DOCX will reject valid uploads until `AllowedTypes` is corrected. Confidence is lowered to medium on this account.
- The upload directory `ContentRootPath/storage/uploads` is already outside `wwwroot` and was left where it is; the fix does not relocate storage. It assumes that directory is not exposed by `UseStaticFiles()` - worth confirming in `Program.cs`, which was not part of the reviewed case.
- No code that serves these files back to clients was visible, so no change was made on the serving side. If such a path exists, it should stream from the private directory through an authorised action that sets the content type from the recorded detected type and sends `Content-Disposition: attachment` with `X-Content-Type-Options: nosniff`.
