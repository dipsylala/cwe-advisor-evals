## Verdict

Exploitable. The code relies on `normalize()` to prevent path traversal, which is textual only and does not follow symbolic links. An attacker can place a symbolic link inside the extraction directory pointing outside of it, and reference that link via the zip entry name to write files outside the intended directory.

## Source

`entry.getName()` from `ZipInputStream.getNextEntry()` at line 12, untrusted archive entry metadata.

## Fix

**Vulnerable code (line 13–18):**
```java
Path target = destination.resolve(entry.getName()).normalize();
if (!target.startsWith(destination)) {
    throw new IOException("entry escapes destination");
}

Files.copy(zip, target);
```

**Fixed code:**
```java
Path canonicalDest = destination.toRealPath();

while ((entry = zip.getNextEntry()) != null) {
    Path target = canonicalDest.resolve(entry.getName());
    
    // Create parent directories to enable canonical path resolution
    Files.createDirectories(target.getParent());
    
    // Resolve to canonical path (follows symlinks)
    Path canonicalTarget = target.toRealPath(java.nio.file.LinkOption.NOFOLLOW_LINKS);
    if (!canonicalTarget.startsWith(canonicalDest)) {
        throw new IOException("entry escapes destination");
    }
    
    Files.copy(zip, canonicalTarget);
}
```

## Explanation

The fix replaces `normalize()` with `toRealPath()`, which canonicalizes the path by following symbolic links and resolving relative components to their real locations. By canonicalizing both the destination (once, outside the loop) and each entry target (inside the loop, after creating parent directories), the containment check now detects and rejects entries that escape the destination directory via symlinks. The parent directory is created before canonicalization to satisfy `toRealPath()` requiring the path to exist; this is necessary for the validation to work correctly. The `LinkOption.NOFOLLOW_LINKS` option prevents symlinks within the resolved path from being followed further, focusing the check on the path structure itself rather than following chains of links.

## Behaviour changes

- **Parent directory creation:** The fix calls `Files.createDirectories(target.getParent())` before copy. The original code did not, meaning it would have failed if parent directories did not exist. This change makes the code more robust by ensuring parents are created, which is necessary for `Files.copy()` to succeed and for `toRealPath()` to work on non-existent files.
- **Destination canonicalization moved outside loop:** The fix canonicalizes `destination` once at the start (outside the loop) and resolves all entries against the canonical destination. This improves performance and ensures consistent validation across all entries.
- **Symlink-aware validation:** The check now uses `Path.toRealPath()` which follows symlinks, replacing the textual `normalize()`. This is the security fix, but it also changes behaviour in that symbolic links are now resolved to their targets when validating containment.
