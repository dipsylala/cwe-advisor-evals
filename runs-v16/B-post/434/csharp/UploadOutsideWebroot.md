## Verdict

**VULNERABLE** - CWE-434 confirmed. The code accepts uploaded files without validating file type (signature or extension) and uses the client-supplied `IFormFile.FileName` directly as the storage path. An attacker can upload executable content (`.aspx`, `.cshtml`, `.html`, `.svg` with script, or other dangerous types) that may be executed or served from the application.

## Source

- **Location**: Line 17, method parameter `IFormFile file`
- **Nature**: User-supplied file upload via HTTP multipart request
- **Trust boundary**: Untrusted client input

## Fix

**Vulnerable code (line 28):**
```csharp
var destination = Path.Combine(uploadRoot, file.FileName);
```

**Fixed code:**
```csharp
// Define allowlist of permitted file types with magic bytes and safe extensions
private static readonly Dictionary<string, (byte[] signature, string extension)> AllowedTypes = new()
{
    { "image/jpeg", (new byte[] { 0xFF, 0xD8, 0xFF }, ".jpg") },
    { "image/png", (new byte[] { 0x89, 0x50, 0x4E, 0x47 }, ".png") },
    { "image/gif", (new byte[] { 0x47, 0x49, 0x46 }, ".gif") },
    { "application/pdf", (new byte[] { 0x25, 0x50, 0x44, 0x46 }, ".pdf") }
};

// In Upload method, after null/empty check:
await using var sourceStream = file.OpenReadStream();
var headerBuffer = new byte[8];
int bytesRead = await sourceStream.ReadAtLeastAsync(headerBuffer, 4, false);

if (bytesRead == 0)
{
    return BadRequest("File is empty");
}

// Validate file signature against allowlist
string detectedType = null;
string safeExtension = null;

foreach (var (mimeType, (signature, ext)) in AllowedTypes)
{
    if (headerBuffer.AsSpan(0, signature.Length).SequenceEqual(signature))
    {
        detectedType = mimeType;
        safeExtension = ext;
        break;
    }
}

if (detectedType is null)
{
    return BadRequest("File type not allowed");
}

// Generate safe filename using GUID + validated extension (not client-supplied)
var safeFileName = Guid.NewGuid().ToString("N") + safeExtension;
var destination = Path.Combine(uploadRoot, safeFileName);

// Rewind stream and write
sourceStream.Seek(0, SeekOrigin.Begin);
await using var destStream = System.IO.File.Create(destination);
await sourceStream.CopyToAsync(destStream);
```

## Explanation

The fix implements three critical controls from CWE-434 remediation:

1. **File signature validation**: Instead of trusting `IFormFile.ContentType` (client-supplied request metadata), the code reads the actual file header bytes and compares them against known magic bytes for allowed types. This detects the real file type regardless of the extension or MIME type the client claims.

2. **Safe filename generation**: The storage filename is generated using `Guid.NewGuid().ToString("N")` rather than using `file.FileName`. The extension is derived from the signature-validated type (via the allowlist map), never from the client-supplied filename. This prevents both path traversal (e.g., `../../evil.aspx`) and type-mismatching attacks (e.g., `.aspx` disguised as an image).

3. **Allowlist enforcement**: Only the defined file types (JPEG, PNG, GIF, PDF) are accepted. Any other file, including executables, scripts, or archives, is rejected. The allowlist defines the canonical extension for each type, so the stored file extension always matches its true content type.

The `ReadAtLeastAsync` call with `false` for `throwOnEndOfStream` ensures the header read succeeds even if the file is smaller than the buffer, and the loop properly compares only the signature bytes (not the full buffer). The stream is rewound before writing to ensure the complete file content is persisted.

## Behaviour changes

- **Acceptance**: Only files with signatures matching the allowlist (JPEG, PNG, GIF, PDF) are accepted; all others are rejected with HTTP 400.
- **Filename**: Storage filename is now a random GUID with a validated extension (e.g., `a1b2c3d4e5f6g7h8.jpg`), not the original client-supplied name.
- **Storage path**: Files continue to be stored outside `wwwroot` (in `uploadRoot`), but the filename is now deterministic and safe; no directory traversal is possible.
- **Response body**: Returns the generated storage filename (e.g., `stored: "a1b2c3d4e5f6g7h8.jpg"`) instead of the client-supplied name.
- **Return codes**: New failure mode: HTTP 400 "File type not allowed" if the file signature does not match any allowed type, or "File is empty" if the stream cannot provide header bytes.

No legitimate business logic is affected; only dangerous or malformed uploads are now blocked.
