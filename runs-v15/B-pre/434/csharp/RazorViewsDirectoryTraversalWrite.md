## Verdict

Exploitable.

## Source

`IFormFile.FileName` parameter from HTTP POST request (line 27, IFormFile `file` parameter), client-supplied and completely untrusted.

## Fix

**Vulnerable code (line 40):**

```csharp
var destinationPath = Path.Combine(viewsRootPath, file.FileName);
```

**Fixed code:**

```csharp
if (file == null || file.Length == 0)
{
    return BadRequest("No file uploaded.");
}

// Validate file content by reading signature
var buffer = new byte[512];
int bytesRead;
using (var stream = file.OpenReadStream())
{
    bytesRead = await stream.ReadAtLeastAsync(buffer, Math.Min(512, (int)file.Length), false);
}

if (!IsValidTemplateFile(buffer.AsSpan(0, bytesRead)))
{
    return BadRequest("File type not allowed for email templates.");
}

// Generate safe filename: never use client-supplied file.FileName
var safeFileName = Guid.NewGuid().ToString("N") + ".cshtml";

// Store outside Views tree to prevent Razor compilation and execution
var templateStoragePath = Path.Combine(_env.ContentRootPath, "PrivateStorage", "EmailTemplates");
Directory.CreateDirectory(templateStoragePath);

var destinationPath = Path.Combine(templateStoragePath, safeFileName);

using (var stream = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write))
{
    await file.CopyToAsync(stream);
}

return Ok(new { stored = safeFileName });

// Helper method to validate file is safe text content
private static bool IsValidTemplateFile(ReadOnlySpan<byte> header)
{
    // Reject binary files (files starting with null bytes)
    for (int i = 0; i < Math.Min(512, header.Length); i++)
    {
        if (header[i] == 0)
            return false;
    }
    // Accept as valid if it contains only text-safe bytes
    return true;
}
```

## Explanation

The vulnerability combines path traversal (attacker controls the filename) with code execution (Razor runtime compilation in the Views tree). The fix eliminates both:

1. **File type validation**: Read the actual file content (signature bytes) and reject files that are not text-based, preventing binary/executable uploads.

2. **Safe filename generation**: Replace the client-supplied `file.FileName` with `Guid.NewGuid().ToString("N")`, removing attacker control over the filename and preventing both path traversal sequences and dangerous extensions.

3. **Storage outside Views tree**: Move storage from `Views/EmailTemplates` (which Razor monitors for compilation) to `PrivateStorage/EmailTemplates`. This prevents Razor runtime compilation from executing uploaded `.cshtml` files even if an attacker bypasses the filename filter.

4. **CreateNew flag**: Use `FileMode.CreateNew` instead of `FileMode.Create` to fail if the destination already exists, preventing accidental overwrite of legitimate files if a GUID collision somehow occurs.

The storage location change is the primary control: even if file validation is bypassed, code stored outside the Views tree is not compiled and executed by Razor. File content validation provides defense-in-depth.

## Behaviour changes

- **Path change**: Files are now stored in `PrivateStorage/EmailTemplates` instead of `Views/EmailTemplates`. The application must serve these files through an authorized action rather than relying on Razor discovery.
- **Filename change**: The API now returns the generated `safeFileName` (a GUID) instead of `file.FileName`. Any client code reading this response will receive the server-generated name.
- **FileMode change**: `CreateNew` instead of `Create`. This is more secure (fails on collision) but does not match the existing behavior if duplicate GUIDs could somehow occur (extremely rare; acceptable trade-off).
- **New method**: `IsValidTemplateFile()` helper added to validate file content. Adds a small performance cost to read 512 bytes from each upload.
- **New exception handling**: `ReadAtLeastAsync` could throw if the stream is shorter than requested. The code gracefully handles short reads with the `throwOnEndOfStream: false` parameter.
- **Validation failure**: Files that fail content validation are now rejected with HTTP 400, preventing upload of binary/executable content.
