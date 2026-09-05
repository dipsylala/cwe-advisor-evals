## Verdict
Exploitable

## Source
User-supplied query parameter `userFile` at line 15 of `UploadsController.cs`

## Fix

**Vulnerable code (line 25):**
```csharp
if (!fullPath.StartsWith(BaseDirectory))
{
    return Forbid();
}
```

**Fixed code:**
```csharp
var relativePath = Path.GetRelativePath(BaseDirectory, fullPath);
if (relativePath == ".." || 
    relativePath.StartsWith(".." + Path.DirectorySeparatorChar) ||
    relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
    Path.IsPathRooted(relativePath))
{
    return Forbid();
}
```

## Explanation
The original `StartsWith()` check performs a string prefix comparison, which is vulnerable to sibling directory bypass attacks. For example, if `BaseDirectory` is `C:\uploads`, a request with `userFile=..\uploads-secret\file.txt` results in `fullPath` of `C:\uploads-secret\file.txt`, which passes the `StartsWith("C:\uploads")` string test but accesses a different directory entirely. The fix uses `Path.GetRelativePath()` to compute the relative path from the base directory to the target file, then verifies it does not escape the base directory by checking that it is not `..`, does not start with `..` followed by a separator (in either form), and is not an absolute path. This path-component-aware comparison correctly rejects sibling bypass attempts while allowing legitimate downloads within the uploads directory.

## Behaviour changes
None. The fix changes only the containment validation logic; the file operation, return value, and function contract remain identical. The check now correctly rejects paths outside the base directory, including sibling directories, which is the intended security boundary.
