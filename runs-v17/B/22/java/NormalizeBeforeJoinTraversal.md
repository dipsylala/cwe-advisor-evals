## Verdict

Exploitable. The current code uses `Path.normalize()` to remove relative operators from user input, but `normalize()` is textual-only and does not follow symlinks or validate the resolved path remains within the base directory. An attacker can plant a symlink in the base directory pointing to a location outside it, or provide a path that bypasses normalization, to read arbitrary files.

## Source

Line 10: `userSuppliedPath` parameter - attacker-controlled string input.

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
        Path base = BASE_DIR.toRealPath();
        Path target = base.resolve(userSuppliedPath).toRealPath();
        
        if (!target.startsWith(base)) {
            throw new IOException("Path traversal attempt detected");
        }
        
        return Files.readAllBytes(target);
    }
}
```

## Explanation

The fix replaces textual-only normalization with cryptographic canonicalization:

1. `BASE_DIR.toRealPath()` canonicalizes the base directory to an absolute path, following any symlinks.
2. `base.resolve(userSuppliedPath).toRealPath()` resolves the user input against the canonical base, then canonicalizes the result—following symlinks and resolving any remaining relative operators like `..` to their real filesystem location.
3. `target.startsWith(base)` verifies the canonicalized target path is still within the base directory using path-component-aware comparison (not string comparison, which would accept siblings like `/var/app-data/reports-backup`).
4. Only after this containment check is the file read with `Files.readAllBytes()`.

This closes the symlink-escape and relative-path-escape vectors. `toRealPath()` will throw `IOException` if the target does not exist, which is the correct behavior—we cannot read a file that does not exist, so validating before the read is appropriate.

## Behaviour changes

**Failure behavior**: The fixed code now throws `IOException` with message "Path traversal attempt detected" if the resolved path escapes the base directory, and propagates `IOException` from `toRealPath()` if the target does not exist. The original code would have silently attempted to read the file regardless of containment.

**Implicit assumptions**:
- `BASE_DIR` must exist and be a directory for `toRealPath()` to succeed. If it does not, an `IOException` is raised before any file read.
- The method already declares `throws IOException`, so the new exception is compatible with the existing contract.

**Return value**: Unchanged—still returns the full byte array from the target file if validation succeeds.
