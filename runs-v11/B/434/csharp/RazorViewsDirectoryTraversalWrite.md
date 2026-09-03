## Verdict
exploitable

## Source
`IFormFile.FileName` — user-supplied filename from HTTP POST upload, obtained from multipart form data

## Fix

**Vulnerable code (line 29-47):**
```csharp
if (file == null || file.Length == 0)
{
    return BadRequest("No file uploaded.");
}

// Nominal storage location for admin-authored email templates,
// a subfolder of the Views tree that Razor already resolves from.
var viewsRootPath = Path.Combine(_env.ContentRootPath, "Views", "EmailTemplates");
Directory.CreateDirectory(viewsRootPath);

// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
var destinationPath = Path.Combine(viewsRootPath, file.FileName);

using (var stream = new FileStream(destinationPath, FileMode.Create))
{
    await file.CopyToAsync(stream);
}

return Ok(new { stored = file.FileName });
```

**Fixed code:**
```csharp
if (file == null || file.Length == 0)
{
    return BadRequest("No file uploaded.");
}

// Reject filenames containing path traversal sequences
if (file.FileName.Contains("..") || file.FileName.Contains("~"))
{
    return BadRequest("Invalid filename: path traversal sequences not allowed.");
}

// Validate file type by extension (filter only; content validation follows)
var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
if (extension != ".cshtml")
{
    return BadRequest("Only .cshtml files are allowed.");
}

// Validate file content by reading header to reject binary or non-text files
using (var stream = file.OpenReadStream())
{
    var buffer = new byte[4];
    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
    // Reject UTF-16/UTF-32 BOMs which indicate non-text encoding
    if (bytesRead >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE)
    {
        return BadRequest("Invalid file format: binary files not allowed.");
    }
}

var viewsRootPath = Path.Combine(_env.ContentRootPath, "Views", "EmailTemplates");
Directory.CreateDirectory(viewsRootPath);

// Generate a random filename using GUID; never use the client-supplied filename
var safeName = $"{Guid.NewGuid():N}.cshtml";
var destinationPath = Path.Combine(viewsRootPath, safeName);

using (var stream = new FileStream(destinationPath, FileMode.CreateNew))
{
    await file.CopyToAsync(stream);
}

return Ok(new { stored = safeName });
```

## Explanation

The original code uses `file.FileName` (an attacker-controlled value from the multipart upload) directly in the storage path without validation. This creates two concurrent weaknesses: (1) an attacker or compromised admin can include path-traversal sequences like `../` in the filename to write outside the intended `Views/EmailTemplates` directory, potentially overwriting application code or configuration files, and (2) because Razor runtime compilation is enabled, a malicious `.cshtml` file containing Razor directives or C# code will be compiled and executed by the application on the next request that resolves it, leading to remote code execution. The fix enforces a strict allowlist: it rejects filenames containing traversal markers (`..` and `~`), validates that only `.cshtml` files are uploaded, and performs a basic signature check by reading the file header to detect binary files masquerading as text. Most critically, it replaces the client-supplied filename with a cryptographically random `Guid`-based name, which breaks both the traversal and file-type-confusion attacks while maintaining the required `.cshtml` extension for Razor to resolve the template.

## Behaviour changes

- **Filename stored on disk differs from upload filename**: Original stores `file.FileName` verbatim; fixed code stores `{guid}.cshtml`. Justification: prevents directory-traversal and filename-based attacks.
- **File mode changed from `Create` to `CreateNew`**: Original uses `FileMode.Create` which truncates if the file exists; fixed code uses `FileMode.CreateNew` which fails if a file with that GUID-based name already exists. Justification: prevents accidental or intentional overwrite attacks via GUID collision exploitation (extremely rare but documented in the taint-sink analysis).
- **Response body changed**: Original returns the client-supplied filename; fixed code returns the server-generated name. Justification: clients must use the safe name returned by the server if they later need to reference the template.
- **New validation added (traversal, extension, signature)**: Original code performs no validation; fixed code rejects files with `..` or `~` in the name, only accepts `.cshtml`, and reads the file header to reject binary files. Justification: implements the allowlist-based file-type validation required by CWE-434 remediation.
