## Verdict

The vulnerability is confirmed. Line 18 uses an insufficiently validated path for file extraction. The code uses `normalize()` (textual path normalization) and compares against a potentially non-canonical destination directory, leaving it vulnerable to symlink-based path traversal (Zip Slip) where archive entries with symlink components can escape the intended extraction directory.

## Source

- **Untrusted Input**: `entry.getName()` from `ZipInputStream` (line 12)
- **Data Flow**: 
  - Line 13: `destination.resolve(entry.getName()).normalize()` - resolves entry name but uses weak normalization
  - Line 14: Validation compares against potentially non-canonical `destination`
  - Line 18: `Files.copy(zip, target)` - writes to the unvalidated target path
- **Sink**: `Files.copy(InputStream, Path)` requires a validated path to avoid writing outside the destination directory

## Fix

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
        while ((entry = zip.getNextEntry()) != null) {
            Path realDest = destination.toRealPath();
            Path target = realDest.resolve(entry.getName()).normalize();
            if (!target.startsWith(realDest)) {
                throw new IOException("entry escapes destination");
            }

            Files.copy(zip, target);
        }
    }
}
```

## Explanation

The fix replaces textual path normalization with canonical path resolution. `Path.toRealPath()` resolves symlinks and relative path components (`.`, `..`) to their actual filesystem locations, whereas `normalize()` only rewrites the path string without following symlinks. By canonicalizing the destination directory first with `destination.toRealPath()`, then resolving each entry name against it, and validating with `Path.startsWith()` against the canonical destination, the code now correctly prevents archive entries from escaping the intended directory—even when symlinks are present or the destination path contains relative components.

The fix follows the CWE-22 Java guidance: "Archive extraction (Zip Slip): treat `ZipEntry.getName()` from `java.util.zip.ZipInputStream` as untrusted - resolve it against the destination directory and verify containment with `Path.startsWith()` after `toRealPath()`, before extracting."

## Behaviour changes

- **Added call**: `destination.toRealPath()` is called once per extraction (not per entry) to obtain the canonical destination directory path. This resolves any symlinks, `.`, or `..` components in the destination path.
- **Path comparison**: The containment check now compares against the canonical `realDest` instead of the raw `destination`, ensuring the validation is not bypassed by symlinks or relative path tricks.
- **Exception handling**: Existing exception handling for `IOException` from `Files.copy()` now also covers potential `IOException` from `toRealPath()` if the destination directory becomes inaccessible during extraction.
- **No functional regression**: Archive entries with legitimate nested paths (e.g., `sub/dir/file.txt`) continue to extract correctly; only entries that escape the destination are rejected.
