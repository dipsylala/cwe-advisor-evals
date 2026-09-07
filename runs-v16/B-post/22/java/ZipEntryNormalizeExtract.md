## Verdict
CONFIRMED - Improper path validation allows zip-slip attacks through symlink-following at extraction.

## Source
Line 13 uses `Path.normalize()` to construct the target path, which is a textual operation that does not follow symlinks. This allows an attacker to plant a symlink entry in a ZIP file (e.g., `escape → /etc`) and then extract an entry pointing to that symlink (e.g., `escape/passwd`). The subsequent `startsWith()` check on line 14 passes because the textual path appears to be within the destination, but `Files.copy()` on line 18 follows the symlink during the actual file operation, writing outside the intended directory.

Additionally, the entry name is not validated to be a single path component, so entries like `../foo` or `foo/bar` are only caught by the `normalize()` + `startsWith()` check. The `normalize()` operation is insufficient against symlink-based traversal and is explicitly ruled out by the guidance.

## Fix
Replace the validation and copy logic to:
1. Canonicalize the destination with `toRealPath()` to follow any existing symlinks in the extraction directory
2. Validate that each entry name is a single path component with no traversal sequences
3. Resolve the entry name against the canonical destination
4. Create parent directories before copying
5. Copy the file

```java
public void extract(ZipInputStream zip, Path destination) throws IOException {
    ZipEntry entry;
    Path canonicalDestination = destination.toRealPath();
    
    while ((entry = zip.getNextEntry()) != null) {
        String entryName = entry.getName();
        
        // Verify entry name is a single path component (rejects ../, ..\\, etc.)
        if (!entryName.equals(Paths.get(entryName).getFileName().toString())) {
            throw new IOException("entry contains path traversal");
        }
        
        // Resolve against the canonical (symlink-resolved) destination
        Path target = canonicalDestination.resolve(entryName);
        
        // Verify containment using path component comparison
        // (redundant after component check above, but defense in depth)
        if (!target.startsWith(canonicalDestination)) {
            throw new IOException("entry escapes destination");
        }
        
        // Create parent directories before copying
        Files.createDirectories(target.getParent());
        
        // Copy the entry
        Files.copy(zip, target);
    }
}
```

## Explanation
The fix replaces `Path.normalize()` with `Path.toRealPath()` applied to the destination. While `toRealPath()` cannot be used on the non-existent target file, applying it to the destination directory (which exists) canonicalizes the entire base path, including any symlinks in the extraction directory itself. This prevents attackers from using symlinks within the destination to escape it.

The entry name is now validated to be a single path component by checking if `Paths.get(name).getFileName().toString()` equals the original name. This rejects traversal sequences like `../`, `..\\`, or embedded slashes (`foo/bar`), eliminating the gap between the textual `normalize()` check and the actual file operation.

The parent directories are created before copying to ensure the operation succeeds when intermediate directories don't yet exist.

## Behaviour changes
- **Entry name validation**: Entries with path separators or traversal sequences are rejected immediately with an `IOException`, rather than relying on textual normalization. This is more explicit and prevents attempts like `../../../etc/passwd` from reaching the copy operation.
- **Symlink handling**: The destination directory is now canonicalized, so any symlinks in the destination path itself are resolved and verified to be within the intended root. This prevents symlink-based escapes even if the attacker has write access to the destination directory between extraction attempts.
- **Parent directory creation**: Parent directories are now created automatically if they don't exist, preventing `Files.copy()` from throwing `NoSuchFileException` when intermediate directories are missing.
- **Trace verification**: The check on line 14 (`if (!target.startsWith(...)`) now operates on paths where the destination has been canonicalized, strengthening the containment guarantee.
