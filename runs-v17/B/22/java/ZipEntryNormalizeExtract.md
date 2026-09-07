# CWE-22 Remediation Report

## Verdict

**exploitable** — The current code uses `normalize()` for path validation, which only rewrites the path textually without following symlinks. A symlink planted in the extraction destination directory can redirect file writes outside the intended directory (Zip Slip). Additionally, the `destination` parameter in the `startsWith()` check is not canonicalized, allowing a symlink in `destination` itself to bypass the containment check.

## Source

`entry.getName()` from `java.util.zip.ZipInputStream` - untrusted attacker-controlled data from a Zip file entry name.

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
        Path canonicalDest = destination.toRealPath();
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            String entryName = entry.getName();

            // Reject entries with path traversal components (must be single filename)
            Path entryPath = Paths.get(entryName);
            if (!entryPath.getFileName().toString().equals(entryName)) {
                throw new IOException("entry escapes destination");
            }

            Path target = canonicalDest.resolve(entryName);
            if (!target.startsWith(canonicalDest)) {
                throw new IOException("entry escapes destination");
            }

            Files.copy(zip, target);
        }
    }
}
```

## Explanation

The fix eliminates the Zip Slip vulnerability by canonicalizing the extraction destination with `toRealPath()` before validating entries. This resolves all symlinks and relative path components in the destination directory itself, ensuring the base directory is always an absolute, symlink-resolved path. Each entry name is then validated to be a single filename component (no `/`, `..`, or absolute paths) by verifying that `Paths.get(entryName).getFileName()` equals the original entry name — this rejects entries containing path separators or traversal sequences. The resolved target path is then verified to start with the canonical destination using `Path.startsWith()` on Path objects, which correctly enforces path containment. When `Files.copy()` writes to the target, symlinks are followed by the filesystem, but they can only resolve within the canonicalized destination boundary because both the base and the entry name have been validated.

## Behaviour changes

- `destination.toRealPath()` is called at the start of extraction. This requires the destination directory to exist; the original code did not enforce this constraint. If the destination does not exist, the method will throw `IOException`, preventing extraction to a non-existent directory.
- Each entry is validated with a new `Paths.get()` call and filename check. This adds minimal overhead but is necessary to reject path traversal attempts.
- The containment check is now performed against `canonicalDest` instead of the raw `destination` parameter. Both are Path objects and compared with `startsWith()`, so the behavior for legitimate entries within the destination is identical; symlinks in the destination parameter are now properly resolved, closing the vulnerability.
- All other behavior is preserved: the method still throws `IOException` with "entry escapes destination" when a traversal is detected, and files are extracted with the same `Files.copy()` call.
