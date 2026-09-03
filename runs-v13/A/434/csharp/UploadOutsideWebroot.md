## Verdict
CWE-434 confirmed. Line 28 uses `file.FileName` directly in the destination path without validation, allowing path traversal attacks and unrestricted file uploads.

## Source
The vulnerable code directly concatenates user-supplied `file.FileName` into the file path without sanitization:

```csharp
var destination = Path.Combine(uploadRoot, file.FileName);
```

An attacker can exploit this by uploading files with names like `../../admin/web.config` or `shell.aspx` to write dangerous files to arbitrary locations or upload executable files.

## Fix
Replace the filename logic with a whitelist-based approach that validates extensions, removes path traversal sequences, and generates a safe filename:

```csharp
// Whitelist allowed extensions
var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".pdf" };

// Extract and validate the extension
var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
if (string.IsNullOrEmpty(extension) || !allowedExtensions.Contains(extension))
{
    return BadRequest("File type not allowed.");
}

// Remove any path traversal sequences from the filename
var safeFileName = Path.GetFileName(file.FileName);
if (safeFileName != file.FileName)
{
    return BadRequest("Invalid filename.");
}

// Generate a unique, safe filename using a GUID
var destination = Path.Combine(uploadRoot, $"{Guid.NewGuid()}{extension}");
```

Replace line 28 with the above validation and filename generation logic before the file creation.

## Explanation
The fix implements three layers of defense:

1. **Extension Whitelist**: Only permit safe file types (images, PDFs) and reject executables (.exe, .asp, .aspx, .php, etc.). The whitelist is checked after normalizing to lowercase to defeat case-based bypasses.

2. **Path Traversal Prevention**: `Path.GetFileName()` strips directory traversal sequences (`../`, `..\`). If the sanitized filename differs from the original, the request is rejected, catching malicious input.

3. **Safe Filename Generation**: Instead of storing user-supplied filenames, generate a unique GUID-based filename with the validated extension. This prevents collisions, directory traversal, and makes filenames unpredictable to attackers.

The `IFormFile.FileName` property is entirely user-controlled and must never be trusted for filesystem operations.
