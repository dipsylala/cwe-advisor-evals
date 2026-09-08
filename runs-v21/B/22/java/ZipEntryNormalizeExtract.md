## Verdict

CONFIRMED: Path traversal vulnerability via symlink escape in ZIP extraction.

## Source

`ZipEntry.getName()` from untrusted ZIP file entries.

## Fix

The vulnerability exists because `Path.normalize()` is textual-only and does not follow symlinks. An attacker can plant a symlink in an earlier ZIP entry (e.g., `sub/link -> ../`) and then use it in a subsequent entry path (e.g., `sub/link/file.txt`) to escape the extraction directory. The textual normalization and `startsWith()` check cannot catch symlinks because they operate before path resolution.

The fix adds two steps after the textual validation:
1. Create parent directories (so symlinks planted by earlier entries now exist)
2. Resolve the parent directory's real path (following symlinks) and verify it remains within the destination's real path

This catches symlinks that earlier entries may have planted, while preserving the initial textual check to reject `..` and absolute paths in the ZIP entry name itself.

### File: ZipExtractor.java

```java
package cases.path;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ZipExtractor {
    public void extract(ZipInputStream zip, Path destination) throws IOException {
        ZipEntry entry;
        Path destinationReal = destination.toRealPath();
        
        while ((entry = zip.getNextEntry()) != null) {
            Path target = destination.resolve(entry.getName()).normalize();
            if (!target.startsWith(destination)) {
                throw new IOException("entry escapes destination");
            }

            // Create parent directories of the target entry
            Path targetParent = target.getParent();
            Files.createDirectories(targetParent);
            
            // Verify the parent's real path (following symlinks) stays within destination
            Path parentReal = targetParent.toRealPath();
            if (!parentReal.startsWith(destinationReal)) {
                throw new IOException("entry escapes destination via symlink");
            }

            Files.copy(zip, target);
        }
    }
}
```

## Explanation

The vulnerability is the classic Zip Slip attack: an attacker can craft a ZIP file containing entries with names that reference paths outside the extraction directory. The original code attempted mitigation using `normalize()` and `startsWith()`, but this check is insufficient because:

1. `normalize()` only removes `..` and `.` components textually; it does not follow symlinks
2. An attacker can plant a symlink in one ZIP entry (e.g., `sub/link -> ../`) and reference it in a later entry (e.g., `sub/link/file.txt`), bypassing the textual check
3. By the time the containment check runs, it only sees the textual path `destination/sub/link/file.txt`, which appears safe

The fix implements the two-phase validation described in CWE-22 guidance for archive extraction:

**Phase 1 (existing):** Textual validation with `normalize()` and `startsWith()` rejects paths containing `..` and absolute paths before they are written.

**Phase 2 (added):** After creating parent directories, canonicalize the parent directory's path by calling `toRealPath()`, which follows all symlinks. This resolves any symlinks planted by earlier ZIP entries. The check `parentReal.startsWith(destinationReal)` then verifies the resolved parent is still within the extraction destination.

The destination path is canonicalized once outside the loop to avoid redundant work.

## Behaviour changes

- The method now calls `destination.toRealPath()` once at the start, which may throw `IOException` if the destination directory does not exist or is inaccessible.
- Each iteration now calls `Files.createDirectories(targetParent)` before writing, ensuring parent directories exist before calling `toRealPath()` on them.
- Each iteration adds a new containment check on the symlink-resolved parent directory path.
- New exception message: "entry escapes destination via symlink" for the post-resolution check (distinct from the textual check's message).
- Extraction now rejects ZIP entries whose parent directory path, when resolved through symlinks, escapes the destination—closing the Zip Slip vulnerability.
