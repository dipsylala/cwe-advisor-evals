## Verdict

The vulnerability is confirmed. Line 15 reads an arbitrary file due to improper path normalization order and missing containment validation.

## Source

`ReportFileReader.java` accepts a user-supplied path and attempts to restrict it to `BASE_DIR` by normalizing and resolving it. However, normalization occurs before resolution, and the final path is never validated to remain within the base directory. This allows:

1. Absolute paths (e.g., `/etc/passwd`) to bypass the base directory entirely, since `Path.resolve()` with an absolute path returns that absolute path unchanged.
2. Traversal sequences (e.g., `../../../etc/passwd`) to escape the base directory.

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
        Path target = BASE_DIR.resolve(userSuppliedPath).normalize();

        if (!target.startsWith(BASE_DIR)) {
            throw new IOException("Path traversal attempt detected");
        }

        return Files.readAllBytes(target);
    }
}
```

## Explanation

The fix reorders the operations and adds containment validation:

1. **Resolve first**: Combine the user-supplied path with `BASE_DIR` using `resolve()` before normalizing. This ensures both absolute and relative paths are processed relative to the base directory.
2. **Normalize after resolution**: Call `normalize()` on the combined path to eliminate redundant `.` and `..` components in the final result.
3. **Verify containment**: Use `Path.startsWith()` to confirm the normalized target path still begins with `BASE_DIR`. Path component comparison ensures `/var/app-data/reports-evil` does not match `/var/app-data/reports`. If the path has escaped, throw an exception and refuse the read.

This defense-in-depth approach prevents both absolute path injection and directory traversal attacks.
