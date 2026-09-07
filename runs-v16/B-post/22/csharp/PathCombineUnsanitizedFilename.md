## Verdict

Confirmed. CWE-22 path traversal via unsanitized `filename` parameter.

## Source

The HTTP GET query parameter `filename` (line 12) is user-controlled and untrusted.

## Fix

```csharp
[HttpGet("view")]
public IActionResult ViewDocument(string filename)
{
    // Reject if filename contains path separators or traversal sequences
    if (string.IsNullOrEmpty(filename) || 
        filename.Contains(Path.DirectorySeparatorChar) ||
        filename.Contains(Path.AltDirectorySeparatorChar) ||
        filename.Contains(".."))
    {
        return BadRequest("Invalid filename");
    }

    var filePath = Path.Combine(_basePath, filename);
    var fullPath = Path.GetFullPath(filePath);
    var basePath = Path.GetFullPath(_basePath);

    // Canonicalize and enforce containment within base directory
    if (!fullPath.StartsWith(basePath + Path.DirectorySeparatorChar) &&
        fullPath != basePath)
    {
        return BadRequest("Access denied");
    }

    var contents = File.ReadAllText(fullPath);

    return Content(contents, "text/plain");
}
```

## Explanation

The original code passes untrusted input directly into `Path.Combine()`, which is unsafe: if `filename` is an absolute path, `Path.Combine()` discards the `_basePath` component entirely. Additionally, relative path traversal sequences (`../`) or encoded variants (`%2e%2e%2f`, decoded by ASP.NET model binding) allow directory escape.

The fix applies three defensive layers:

1. **Input rejection** (line 9-14): Reject `filename` if it contains any path separator (`\`, `/`) or traversal marker (`..`). This catches common attack patterns immediately and ensures the value remains a single filename component.

2. **Canonicalization** (line 16-18): Convert both the constructed path and the base directory to absolute canonical form using `Path.GetFullPath()`. This resolves relative references (`.`, `..`) to their true locations.

3. **Containment validation** (line 20-24): Verify the canonicalized path stays within the base directory by ensuring it starts with `basePath + separator` (preventing sibling directory escape like `/var/app/documents-secret`) or equals the base directory exactly. Using a trailing separator avoids the string-prefix collision (`/app/uploads` contains `/app/uploads-secret` as a string prefix but not as a path component).

A successful request now requires `filename` to be a simple name with no separators or traversal markers, and the resolved file must land within the intended directory tree.

## Behaviour changes

- Requests with `..`, `/`, or `\` in the filename now return 400 Bad Request instead of attempting the file read.
- Absolute paths in the filename are rejected as invalid (400).
- Encoded traversal sequences like `%2e%2e%2f` are decoded by model binding to `../`, then rejected by the validation check.
- Paths that resolve outside the base directory return 400 instead of reading unauthorized files.
- The return type and success case (HTTP 200 with file contents) remain unchanged for valid single-component filenames.
