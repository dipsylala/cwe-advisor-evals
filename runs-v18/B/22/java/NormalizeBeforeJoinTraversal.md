## Verdict

Exploitable. The code uses `Path.normalize()` which performs only string normalization and does not resolve symlinks. An attacker can create a symbolic link within the base directory that points to a file outside it, then reference that symlink to read arbitrary files. Additionally, there is no containment verification after path resolution to confirm the target remains within the base directory.

## Source

User-supplied path from `readReport(String userSuppliedPath)` parameter on line 10.

## Fix

### File: ReportFileReader.java

```java
package cases.pathtraversal;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ReportFileReader {
    private static final Path BASE_DIR = Path.of("/var/app-data/reports");

    public byte[] readReport(String userSuppliedPath) throws IOException {
        Path baseDir = BASE_DIR.toRealPath();
        Path target = baseDir.resolve(userSuppliedPath).toRealPath();
        
        // Verify the resolved path is within the base directory
        if (!target.startsWith(baseDir)) {
            throw new IOException("Path traversal attempt detected");
        }

        return Files.readAllBytes(target);
    }
}
```

## Explanation

The fix replaces `Path.normalize()` with `Path.toRealPath()` to fully canonicalize paths, which resolves symbolic links and relative references to their real form. This closes the symlink-based traversal vector. The base directory is also canonicalized by calling `toRealPath()` on it. A containment check is added after canonicalization using `Path.startsWith(Path)` to verify the resolved target path remains within the base directory before reading the file. This enforces the primary defence: reject requests that attempt to traverse outside the intended directory. The exception thrown on traversal attempt provides clear feedback for logging and monitoring.

## Behaviour changes

- `toRealPath()` is called on `BASE_DIR` each time the method is invoked, adding a small overhead compared to the original. This is necessary to ensure the base directory itself is canonicalized in the same way as the target for accurate comparison.
- The method now throws `IOException` with the message "Path traversal attempt detected" if the resolved path is not contained within the base directory, whereas the original code would have allowed such traversal.
- `toRealPath()` on the target path will throw `IOException` if the requested file does not exist, which is appropriate for a read operation since the file should exist; this differs from the original which would simply fail with a file-not-found error from `Files.readAllBytes()`.

The sink contract is preserved: the method still returns `byte[]` from `Files.readAllBytes()` for valid, contained paths, and throws `IOException` on error.

