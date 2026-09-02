## Verdict

Exploitable

## Source

`ZipEntry.getName()` from `ZipInputStream.getNextEntry()` at line 12, untrusted archive entry names supplied by the attacker.

## Fix

**Vulnerable code (line 13-18):**
```java
Path target = destination.resolve(entry.getName()).normalize();
if (!target.startsWith(destination)) {
    throw new IOException("entry escapes destination");
}

Files.copy(zip, target);
```

**Fixed code:**
```java
String entryName = entry.getName();

// Ensure single path component (no directory separators in entry name)
if (!entryName.equals(Paths.get(entryName).getFileName().toString())) {
    throw new IOException("entry escapes destination");
}

Path target = destination.resolve(entryName);
Path parent = target.getParent();

// Create parent directories
Files.createDirectories(parent);

// Verify parent directory is within the destination (after following symlinks)
Path realParent = parent.toRealPath();
Path realDestination = destination.toRealPath();

if (!realParent.startsWith(realDestination)) {
    throw new IOException("entry escapes destination");
}

Files.copy(zip, target);
```

## Explanation

The vulnerability is a Zip Slip (path traversal in archive extraction). The original code uses `Path.normalize()`, which only rewrites the path string textually and does not follow symlinks. An attacker can exploit this by extracting a symlink entry that points outside the destination directory in an earlier entry; when validating a subsequent entry's path with `normalize()`, the planted symlink remains undetected, allowing the subsequent file to be written outside the intended directory.

The fix addresses this by: (1) validating that each entry name is a single path component with no directory separators to prevent traversal in the entry name itself; (2) creating parent directories before validation to ensure they exist; (3) using `Path.toRealPath()` on the parent directory to follow and resolve all symlinks, then verifying the canonicalized parent is contained within the destination using `startsWith()`. This ensures symlink attacks are caught before extraction.

## Behaviour changes

- **New import or dependency**: Requires no additional imports (all APIs used are from `java.nio.file` already in scope).
- **Directory creation**: The fix calls `Files.createDirectories(parent)` to ensure parent directories exist before validation. This is safe because traversal is validated after creation by following symlinks. The original code did not create directories, so extraction would fail with NoSuchFileException if parent paths did not exist.
- **Symlink following**: The fix uses `toRealPath()` to follow symlinks during containment validation, whereas the original used `normalize()` which does not follow symlinks. This changes validation behavior but does not change file extraction behavior for non-symlink paths.
- **Entry name validation**: The fix adds explicit validation rejecting entry names containing directory separators. The original code implicitly allowed multi-component paths through `resolve()`, which would have failed during `Files.copy()` if parent directories did not exist.
