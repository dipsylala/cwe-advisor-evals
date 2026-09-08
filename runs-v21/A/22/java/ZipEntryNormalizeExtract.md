## Verdict

Confirmed. The code has a path traversal vulnerability via symlinks in parent directories.

## Source

**File:** `ZipExtractor.java`
**Line:** 18

The `Files.copy(zip, target)` call writes to a path whose parent directories may contain symlinks pointing outside the destination directory. The existing normalization check validates only the logical path, not the real filesystem path.

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
        Path canonicalDest = destination.toRealPath();
        
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            Path target = destination.resolve(entry.getName()).normalize();
            
            // Check logical path is within destination
            if (!target.startsWith(destination)) {
                throw new IOException("entry escapes destination");
            }
            
            // Create and validate parent directories
            Path parent = target.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
                
                // Verify real path of parent is within canonical destination
                Path realParent = parent.toRealPath();
                if (!realParent.startsWith(canonicalDest)) {
                    throw new IOException("entry escapes destination");
                }
            }
            
            Files.copy(zip, target);
        }
    }
}
```

## Explanation

The fix adds two critical checks:

1. **Canonical destination path:** `canonicalDest = destination.toRealPath()` resolves the destination to its real filesystem path, accounting for any symlinks in the destination itself.

2. **Parent directory validation:** After creating parent directories with `Files.createDirectories(parent)`, the code now calls `parent.toRealPath()` to get the real filesystem path and verifies it starts with `canonicalDest`. This catches attacks where:
   - A parent directory component is a symlink pointing outside the destination
   - A parent directory is replaced with a symlink between path resolution and file creation

This layered approach handles both logical path traversal (via the initial `startsWith` check) and symlink-based escapes (via the real-path validation of parent directories).
