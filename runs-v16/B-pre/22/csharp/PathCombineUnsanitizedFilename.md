## Verdict

exploitable

## Source

The `filename` parameter from the HTTP GET query string (line 12) is user-controlled and flows directly into the file path without validation.

## Fix

**Vulnerable code (line 14-17):**
```csharp
var filePath = Path.Combine(_basePath, filename);

// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
var contents = File.ReadAllText(filePath);
```

**Fixed code:**
```csharp
// Canonicalize the combined path
var filePath = Path.GetFullPath(Path.Combine(_basePath, filename));
var basePathFull = Path.GetFullPath(_basePath);

// Verify the resolved path stays within the base directory
var relativePath = Path.GetRelativePath(basePathFull, filePath);
if (relativePath == ".." ||
    relativePath.StartsWith(".." + Path.DirectorySeparatorChar) ||
    relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
    Path.IsPathRooted(relativePath))
{
    return BadRequest("Invalid file path");
}

var contents = File.ReadAllText(filePath);
```

## Explanation

The original code is vulnerable to path traversal because `Path.Combine()` does not validate that user input stays within the base directory; a user providing `../../../etc/passwd` or an absolute path escapes the intended directory. The fix canonicalizes both paths using `Path.GetFullPath()`, which normalizes `..` sequences and converts relative paths to absolute form, then uses `Path.GetRelativePath()` to compute the relative path from the base directory to the target. It rejects the request if the relative path escapes the base (indicated by starting with `..`), is absolute, or cannot be contained. This ensures only files within the base directory can be accessed.

## Behaviour changes

- Added canonicalization of `filePath` using `Path.GetFullPath()` to resolve relative path sequences (`..`, `.`) and convert to absolute form before validation.
- Added computation of `basePathFull` by canonicalizing `_basePath` for consistent comparison.
- Added validation check that rejects paths escaping the base directory by checking if `relativePath` is `..`, starts with `..` followed by a separator (testing both forward and back slashes), or is rooted.
- Added early return with `BadRequest()` HTTP 400 response when path validation fails, preventing the file read operation.
- The successful case (valid paths within the base directory) preserves the original contract: `File.ReadAllText()` is still called with the validated canonical path, and the response type and status remain unchanged.

