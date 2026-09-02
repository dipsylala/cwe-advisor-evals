## Verdict

CWE-434 confirmed. The code accepts `IFormFile.FileName` without validation, allowing an attacker to upload files with arbitrary extensions or use path traversal sequences (e.g., `../../`) to write outside the intended directory.

## Source

Line 28: `var destination = Path.Combine(uploadRoot, file.FileName);`

The `file.FileName` property is attacker-controlled via the HTTP request and is used directly in the file path with no validation.

## Fix

```csharp
[HttpPost("/upload")]
public async Task<IActionResult> Upload(IFormFile file)
{
    if (file is null || file.Length == 0)
    {
        return BadRequest();
    }

    // Whitelist allowed file extensions
    var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".pdf" };
    var fileExtension = Path.GetExtension(file.FileName).ToLowerInvariant();
    if (!allowedExtensions.Contains(fileExtension))
    {
        return BadRequest("Invalid file type");
    }

    // Validate filename does not contain path traversal
    var fileName = Path.GetFileName(file.FileName);
    if (fileName != file.FileName || fileName.Contains(".."))
    {
        return BadRequest("Invalid filename");
    }

    var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
    Directory.CreateDirectory(uploadRoot);

    // Generate a safe filename to prevent collisions and attacks
    var safeFileName = $"{Guid.NewGuid()}{fileExtension}";
    var destination = Path.Combine(uploadRoot, safeFileName);

    await using var stream = System.IO.File.Create(destination);
    await file.CopyToAsync(stream);

    return Ok(new { stored = Path.GetFileName(destination), bytes = file.Length });
}
```

## Explanation

The fix implements three layers of defense:

1. **Extension Whitelist**: Only allow safe file extensions (`.jpg`, `.png`, `.pdf`, etc.) and reject dangerous types (`.exe`, `.dll`, `.bat`, etc.).

2. **Path Traversal Validation**: Use `Path.GetFileName()` to extract only the filename component and verify it matches the original input. If they differ, the input contained directory traversal sequences like `../`. Additionally, check for `..` explicitly.

3. **Safe Filename Generation**: Replace the user-supplied filename with a GUID-based name combined with the validated extension. This prevents both extension-based attacks and filename collisions while ensuring the stored filename is entirely under application control.

The allowed extensions should be adjusted to match your application's actual requirements. Consider adding additional validation such as file size limits and MIME type verification for defense-in-depth.
