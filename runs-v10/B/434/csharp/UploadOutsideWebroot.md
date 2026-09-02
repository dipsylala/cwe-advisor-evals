## Verdict

Exploitable. The code accepts `file.FileName` directly from the HTTP request without validating file type or content. An attacker can upload executable files (`.exe`, `.dll`, `.aspx`, etc.) or use path traversal sequences in the filename to write files outside the intended directory, leading to arbitrary code execution or unauthorized file placement.

## Source

`file.FileName` parameter from `IFormFile` on line 17, which is client-supplied HTTP request metadata.

## Fix

**Vulnerable code (lines 24-31):**
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

// Validate file signature
byte[] buffer = new byte[4];
await using var readStream = file.OpenReadStream();
int bytesRead = await readStream.ReadAsync(buffer, 0, 4);

if (bytesRead == 0)
{
    return BadRequest();
}

// Define allowed file types by signature
var allowedSignatures = new (byte[] sig, string ext)[]
{
    (new byte[] { 0xFF, 0xD8, 0xFF }, "jpg"),
    (new byte[] { 0x89, 0x50, 0x4E, 0x47 }, "png"),
    (new byte[] { 0x47, 0x49, 0x46 }, "gif"),
    (new byte[] { 0x25, 0x50, 0x44, 0x46 }, "pdf")
};

string? extension = null;
foreach (var (sig, ext) in allowedSignatures)
{
    if (buffer.AsSpan(0, Math.Min(bytesRead, sig.Length)).SequenceEqual(sig))
    {
        extension = ext;
        break;
    }
}

if (extension == null)
{
    return BadRequest();
}

// Generate safe filename
var safeFileName = Guid.NewGuid().ToString("N") + "." + extension;
var destination = Path.Combine(uploadRoot, safeFileName);

// Rewind and write
readStream.Seek(0, SeekOrigin.Begin);
await using var writeStream = System.IO.File.Create(destination, FileMode.CreateNew);
await readStream.CopyToAsync(writeStream);

return Ok(new { stored = Path.GetFileName(destination), bytes = file.Length });
```

## Explanation

The fix replaces the client-supplied filename with a server-generated name and validates file type by inspecting actual content (magic bytes) rather than trusting the filename extension. The original code used `file.FileName` directly, which is attacker-controlled and can contain path traversal sequences like `..` or absolute paths. The fix reads the file's signature bytes, matches them against an allowlist of permitted types (JPEG, PNG, GIF, PDF), and generates a new filename using `Guid.NewGuid().ToString("N")` combined with the extension derived from the validated content type. This eliminates two attack vectors: uploading malicious file types and writing files outside the intended directory. The file is stored with a generated name that prevents both traversal attacks and trivial filename guessing.

## Behaviour changes

- **Signature validation added**: The code now reads the first 4 bytes of the uploaded file and validates against known magic numbers. Files with mismatched signatures or disallowed types are rejected with a 400 BadRequest response.
- **Filename generation**: The storage filename is now server-generated using GUID rather than client-supplied. The original filename is no longer used or accessible after validation, preventing path traversal and filename-based attacks.
- **Extension mapping**: The file extension in storage is now derived from the detected content type (from the allowlist) rather than the client-supplied filename, preventing extension-swapping attacks.
- **Seek operation**: The read stream is rewound to the beginning (`Seek(0, SeekOrigin.Begin)`) after signature validation so the full file content is copied, not just the remainder after the 4-byte read.
- **FileMode.CreateNew**: `System.IO.File.Create()` is now called with explicit `FileMode.CreateNew` parameter instead of relying on the default `FileMode.Create`. This ensures the operation fails if a file with that path already exists (defense against race conditions), though with a GUID-based filename this is extremely unlikely.
