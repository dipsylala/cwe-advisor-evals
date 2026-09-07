## Verdict

**EXPLOITABLE**

The code constructs archive extraction paths from untrusted `ZipEntry.getName()` input without sufficient canonicalization. While the code checks for escape using `Path.startsWith()`, it validates against a path that has been only textually normalized (`.normalize()`), not canonicalized via `toRealPath()`. This leaves symlink-based escape routes open: a crafted zip containing a symlink pointing outside the destination directory would pass the check if the symlink path is textually within the destination after normalization.

## Source

`entry.getName()` from `java.util.zip.ZipInputStream` - untrusted archive entry name supplied by an attacker who controls the zip file contents.

## Fix

### File: ZipExtractor.java

```java
package cases.path;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ZipExtractor {
    public void extract(ZipInputStream zip, Path destination) throws IOException {
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            String entryName = entry.getName();
            
            // Reject entry names that are not a single path component
            if (entryName.isEmpty() || !entryName.equals(Paths.get(entryName).getFileName().toString())) {
                throw new IOException("entry contains path traversal");
            }
            
            Path target = destination.resolve(entryName);
            
            // Canonicalize the destination and verify containment
            Path canonicalDestination = destination.toRealPath();
            Path parentPath = target.getParent().toRealPath();
            
            if (!parentPath.startsWith(canonicalDestination)) {
                throw new IOException("entry escapes destination");
            }
            
            Files.copy(zip, target);
        }
    }
}
```

## Explanation

The fix addresses Zip Slip by applying three defences:

1. **Single-component validation:** The entry name is checked to ensure it does not contain path separators (`/` or `\`) or traversal sequences (`..`). The check `!entryName.equals(Paths.get(entryName).getFileName().toString())` leverages the fact that `getFileName()` returns only the final component; any path separators cause a mismatch and trigger rejection. This prevents an attacker from extracting files into subdirectories that could contain escape routes.

2. **Symlink-aware canonicalization:** The code replaces `.normalize()` (textual path rewriting that leaves symlinks in place) with `.toRealPath()` (which resolves symlinks to their targets). Since the extraction target does not yet exist, `toRealPath()` is applied to the parent directory `target.getParent()`, which does exist. This allows detection of symlinks in the directory structure.

3. **Canonical containment check:** The `Path.startsWith(Path)` comparison is applied to both the canonicalized destination and the canonicalized parent directory, ensuring the comparison operates on real paths rather than textual forms. This prevents a crafted symlink from bypassing the boundary check.

The guidance prohibits using `normalize()` for archive extraction because it is purely textual: `Path.normalize()` rewrites `.` and `..` in the string representation without resolving symbolic links, leaving symlink-based directory escapes open.

## Behaviour changes

- Zip entries with path separators or traversal sequences are now rejected with `IOException`, rather than potentially extracted. Extraction is restricted to flat archives where all entries are single filenames in the destination directory. This is a **breaking change** for archives containing subdirectories—the application must reject such archives or redesign to allow explicit subdirectory allowlists mapped to fixed extraction paths.
- The application now follows symbolic links in the destination directory hierarchy and rejects extraction if a symlink would cause the target to land outside the permitted base. This may surface previously hidden symlinks in the destination tree.

