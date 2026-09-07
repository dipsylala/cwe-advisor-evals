## Verdict
exploitable

## Source
Line 10: `userSuppliedPath` parameter (untrusted user input)

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
        // Resolve the path against the base directory
        Path target = BASE_DIR.resolve(userSuppliedPath).toRealPath();

        // Canonicalize the base directory for comparison
        Path baseReal = BASE_DIR.toRealPath();

        // Verify the resolved path is contained within the base directory
        if (!target.startsWith(baseReal)) {
            throw new IOException("Path traversal attempt: resolved path is outside base directory");
        }

        return Files.readAllBytes(target);
    }
}
```

## Explanation
The original code uses `Path.normalize()`, which is textual-only and does not verify that the resolved path stays within the base directory. An attacker can supply an absolute path (e.g. `/etc/passwd`) which, when resolved via `BASE_DIR.resolve()`, bypasses the base directory constraint entirely. The fix replaces `normalize().toString()` with `toRealPath()`, which canonicalizes the path and resolves symlinks, then adds a mandatory containment check using `Path.startsWith()` after canonicalizing the base directory the same way. This ensures all paths, regardless of input format (relative, absolute, or symlink-containing), stay within the intended base directory before the file is accessed.

## Behaviour changes
- `toRealPath()` throws `IOException` if the target file does not exist, whereas `normalize()` silently processes non-existent paths. Since the original code passes the result directly to `Files.readAllBytes()`, which also throws `IOException` for missing files, the observable behavior is the same: both fail when the file is not found.
- The explicit containment check adds a new exception type (thrown with message "Path traversal attempt") when the resolved path is outside the base directory. In the original code, an absolute path like `/etc/passwd` would be accessed directly, bypassing BASE_DIR entirely. The fixed code rejects this case before the file operation.
- Symlinks are now followed during canonicalization. The original code's use of `normalize()` leaves symlinks as path components unchanged. The fix resolves them, ensuring that a symlink pointing outside BASE_DIR cannot be used to escape the boundary.

## Verification
Compiled with `javac ReportFileReader.java`: success. No new dependencies introduced. All new APIs (`Path.toRealPath()`, `Path.startsWith()`) are from `java.nio.file`, part of the Java standard library since Java 7.

## Assumptions
None.
