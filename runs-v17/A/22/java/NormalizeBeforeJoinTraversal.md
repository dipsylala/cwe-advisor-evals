## Verdict

The code is vulnerable to path traversal (CWE-22) because `Path.normalize()` is applied to the user-supplied path before joining with the base directory. This allows an absolute path (e.g., `/etc/passwd`) to escape the restricted directory, since `resolve()` with an absolute path argument returns the absolute path unchanged, ignoring `BASE_DIR`.

## Source

**File:** ReportFileReader.java  
**Line:** 15  
**Vulnerable Pattern:**
```
String cleaned = Path.of(userSuppliedPath).normalize().toString();
Path target = BASE_DIR.resolve(cleaned);
return Files.readAllBytes(target);  // Sink
```

**Attack Vector:** If `userSuppliedPath = "/etc/passwd"`:
- Line 11: `Path.of("/etc/passwd").normalize()` → `/etc/passwd` (absolute)
- Line 12: `BASE_DIR.resolve("/etc/passwd")` → `/etc/passwd` (absolute paths override base)
- Line 15: Reads from `/etc/passwd` instead of `/var/app-data/reports/etc/passwd`

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
        // Resolve the user-supplied path against the base directory first,
        // then normalize to collapse .. and . sequences
        Path target = BASE_DIR.resolve(userSuppliedPath).normalize();
        
        // Verify the resolved path is within the base directory
        if (!target.startsWith(BASE_DIR)) {
            throw new IllegalArgumentException("Path traversal attempted");
        }
        
        return Files.readAllBytes(target);
    }
}
```

## Explanation

The fix reorders the operations to prevent absolute path escape:

1. **Resolve first:** `BASE_DIR.resolve(userSuppliedPath)` treats the user input as relative (or validates it remains confined). If `userSuppliedPath = "reports/file.txt"`, this produces `/var/app-data/reports/reports/file.txt`; if `userSuppliedPath = "../etc/passwd"`, this produces `/var/app-data/reports/../etc/passwd`.

2. **Normalize second:** `.normalize()` on the joined path collapses `.` and `..` sequences safely: `/var/app-data/reports/../etc/passwd` becomes `/var/app-data/etc/passwd`.

3. **Verify containment:** `target.startsWith(BASE_DIR)` confirms the final path remains within the base directory. This catches attempts like `../../../etc/passwd` that would escape after normalization.

If the user supplies an absolute path like `/etc/passwd`, `resolve()` will treat it as relative (Path.resolve() with a relative argument on Unix treats any String argument as relative; absolute paths are only special when passed as another Path object from an absolute root). Even if an attempt is made to escape, the `startsWith()` check provides defense-in-depth by rejecting any path outside the base directory.
