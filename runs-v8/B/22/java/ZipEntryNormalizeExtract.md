## Verdict

CONFIRMED. The code uses `Path.normalize()` instead of `Path.toRealPath()` for archive extraction path validation, which is insufficient to prevent symlink-based path traversal (Zip Slip).

## Source

Untrusted input from `entry.getName()` supplied by `ZipInputStream.getNextEntry()`. The entry name is attacker-controlled and embedded in the zip file.

## Fix

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
            
            // Ensure entry name is a single path component (no separators or traversal)
            if (!Paths.get(entryName).getFileName().toString().equals(entryName)) {
                throw new IOException("entry name contains path separators or traversal sequences");
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

Three changes eliminate the weakness:

1. **Canonicalize the destination directory** using `toRealPath()` at the start of extraction. This resolves any symbolic links in the destination path itself, ensuring the containment check is based on the actual filesystem location, not a path that may bypass validation through symlink indirection.

2. **Verify the entry name is a single path component** by checking that `Paths.get(entryName).getFileName().toString()` equals the original entry name. This rejects names containing path separators (`/` or `\`) or traversal sequences like `../`, which would escape the destination directory when resolved.

3. **Use the canonicalized destination** for path resolution and containment checking. This ensures that `resolve()` and `startsWith()` operate on absolute canonical paths, not symbolic-link-containing relative paths.

The original code's use of `normalize()` only rewrites the path textually without resolving symlinks. An attacker could embed a symbolic link in the zip that points outside the extraction directory; after `normalize()`, the path still passes the `startsWith()` check because it appears to be inside the destination, but the symlink's target may actually escape. By requiring both canonicalization and single-component entry names, the fix closes this gap.

## Behaviour changes

- **Rejects entry names with path separators**: Entries like `subdir/file.txt` or `../etc/passwd` will now throw `IOException` instead of being extracted. This is a hardening change that prevents directory traversal through entry names.
- **Resolves symbolic links in the destination path**: If the destination path itself contains symbolic links, they are now resolved to their canonical locations. This prevents attackers from bypassing containment checks through symlinks in the extraction target.
- **May fail on non-existent destination**: If the destination directory does not exist, `toRealPath()` will throw `IOException` instead of creating the path. The caller must ensure the destination directory exists before extraction begins (this is typical for extraction operations).

