## Verdict

Valid finding. The `filename` parameter from the HTTP request is passed directly to `Path.Combine()` without validation, enabling path traversal. `Path.Combine()` does not prevent traversal: if any argument after the first is an absolute path, or if the argument starts with `..`, the base directory is discarded entirely.

## Source

User-supplied `filename` parameter from the HTTP GET route (line 12, method parameter) flows through:
1. Line 14: `Path.Combine(_basePath, filename)` — combines unvalidated input with base path
2. Line 17: `File.ReadAllText(filePath)` — reads the unvalidated filesystem path (sink)

An attacker can supply `filename` values like `../../../etc/passwd` or `C:\Windows\System32\config\SAM` to escape the intended base directory.

## Fix

```csharp
[HttpGet("view")]
public IActionResult ViewDocument(string filename)
{
    string baseFullPath = Path.GetFullPath(_basePath);
    string fullPath = Path.GetFullPath(Path.Combine(baseFullPath, filename));
    
    string relativePath = Path.GetRelativePath(baseFullPath, fullPath);
    if (relativePath == ".." || 
        relativePath.StartsWith(".." + Path.DirectorySeparatorChar) || 
        relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
        Path.IsPathRooted(relativePath))
    {
        return BadRequest();
    }
    
    var contents = File.ReadAllText(fullPath);
    return Content(contents, "text/plain");
}
```

## Explanation

The fix applies three steps from the CWE-22 C# guidance:

1. **Canonicalize**: `Path.GetFullPath()` resolves the combined path to an absolute canonical form, converting relative references like `..` to their true location.

2. **Validate containment**: `Path.GetRelativePath(baseFullPath, fullPath)` computes the relative path from the base. If the result is `..` (one level up), starts with `..` followed by a separator (escaping), or is rooted (absolute path), the input attempted to escape.

3. **Reject, do not strip**: The validation rejects the input outright rather than attempting to sanitize or remove traversal sequences, which can be bypassed through double-encoding or other evasions.

After validation passes, `fullPath` is guaranteed to be inside `baseFullPath` and is safe to pass to `File.ReadAllText()`.

## Behaviour changes

- **Before**: Accepts any filename, including `../../../etc/passwd`, `..\..\windows\system32\config\sam`, `C:\Windows\System32\config\SAM`, and percent-encoded variants. Attacker reads arbitrary files.
- **After**: Accepts only filenames that canonicalize to paths inside the base directory. Rejects all `..`, `.\`, absolute paths, and rooted path components with `BadRequest()`. Attacker cannot escape the base directory.
