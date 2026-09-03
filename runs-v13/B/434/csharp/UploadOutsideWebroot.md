## Verdict

Exploitable. The client-supplied `file.FileName` is used directly in `Path.Combine()` without validation. An attacker can upload a file with a dangerous extension (e.g., `.exe`, `.aspx`, `.cshtml`), a path traversal sequence in the filename (e.g., `../../../etc/passwd` or `..\..\..\important.config`), or content mismatched to its extension. The storage is outside `wwwroot`, which limits immediate web execution, but traversal sequences can still reach sensitive application directories (particularly the views tree if `AddRazorRuntimeCompilation()` is enabled).

## Source

`file.FileName` (line 17, parameter from multipart request) → used directly at line 28 in `Path.Combine(uploadRoot, file.FileName)`.

## Fix

**Vulnerable code:**
```csharp
var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
Directory.CreateDirectory(uploadRoot);

// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
var destination = Path.Combine(uploadRoot, file.FileName);

await using var stream = System.IO.File.Create(destination);
await file.CopyToAsync(stream);
```

**Fixed code:**
```csharp
var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
Directory.CreateDirectory(uploadRoot);

// Validate file signature and generate safe filename
var allowedSignatures = new Dictionary<byte[], string>
{
    { new byte[] { 0xFF, 0xD8, 0xFF }, "jpg" },      // JPEG
    { new byte[] { 0x89, 0x50, 0x4E, 0x47 }, "png" }, // PNG
    { new byte[] { 0x47, 0x49, 0x46 }, "gif" },      // GIF
    { new byte[] { 0x25, 0x50, 0x44, 0x46 }, "pdf" } // PDF
};

var buffer = new byte[8];
await using (var readStream = file.OpenReadStream())
{
    int bytesRead = await readStream.ReadAtLeastAsync(buffer, buffer.Length, throwOnEndOfStream: false);
    if (bytesRead == 0)
    {
        return BadRequest("File is empty");
    }
}

string? detectedExtension = null;
foreach (var sig in allowedSignatures)
{
    if (buffer.AsSpan(0, sig.Key.Length).SequenceEqual(sig.Key))
    {
        detectedExtension = sig.Value;
        break;
    }
}

if (detectedExtension is null)
{
    return BadRequest("File type not allowed");
}

// Generate safe filename using server-generated name
var safeFileName = $"{Guid.NewGuid():N}.{detectedExtension}";
var destination = Path.GetFullPath(Path.Combine(uploadRoot, safeFileName));

// Ensure the resolved path stays within uploadRoot (path traversal check)
if (!destination.StartsWith(Path.GetFullPath(uploadRoot) + Path.DirectorySeparatorChar))
{
    return BadRequest("Invalid file path");
}

await using var stream = System.IO.File.Create(destination, bufferSize: 4096, useAsync: true);
await file.CopyToAsync(stream);

return Ok(new { stored = safeFileName, bytes = file.Length });
```

## Explanation

The fix enforces three key defenses. First, it reads the file's magic bytes and validates them against an allowlist of permitted signatures (JPEG, PNG, GIF, PDF shown as example). This ensures the file's actual content matches its claimed type—a client cannot upload a `.jpg` file containing executable content. Second, it generates a completely new filename using `Guid.NewGuid()` instead of trusting the client-supplied `IFormFile.FileName`, eliminating path traversal attacks like `../../../config.json` or double-extension tricks like `shell.aspx.jpg`. Third, it verifies the resolved path stays within the upload directory using `Path.GetFullPath()` and a bounds check, preventing escapes even if the filename manipulation somehow bypasses GUID generation. The extension is mapped from the detected signature, not the client filename, so attackers cannot control how the file is later handled. Upload size validation should be added via `[RequestSizeLimit]` on the action method to complement this fix.

## Behaviour changes

The response format changed from `{ stored = Path.GetFileName(destination), ... }` to `{ stored = safeFileName, ... }`. The `stored` value is now a server-generated GUID with a detected extension (e.g., `a1b2c3d4e5f6g7h8.png`) instead of the original filename, which is the intended behavior to prevent filename-based attacks. The stored path is guaranteed to be within `uploadRoot` after validation. File creation now uses `FileMode.Create` (implicit) with async flags for better resource management. These changes do not alter the API contract meaningfully—the response still contains the stored filename and byte count—but the filename is now server-controlled and collision-resistant.
