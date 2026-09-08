## Verdict
Exploitable

## Source
`userSuppliedPath` parameter - untrusted user-supplied string

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
        // Resolve the user-supplied path relative to BASE_DIR
        Path candidate = BASE_DIR.resolve(userSuppliedPath);
        
        // Canonicalize the candidate path to resolve symlinks and relative paths
        Path target = candidate.toRealPath();
        
        // Canonicalize the base directory for containment comparison
        Path baseReal = BASE_DIR.toRealPath();
        
        // Verify the resolved path stays within the base directory
        if (!target.startsWith(baseReal)) {
            throw new IllegalArgumentException("Path traversal detected");
        }

        return Files.readAllBytes(target);
    }
}
```

## Explanation
The original code used `Path.normalize()` to process user input, but `normalize()` only performs textual path manipulation and does not resolve symbolic links. This allows an attacker to create a symlink under the base directory pointing outside it (e.g., `/var/app-data/reports/link` → `/etc`), and then access arbitrary files by supplying `link/passwd`. The fix replaces `normalize()` with `toRealPath()`, which follows symlinks and resolves the true canonical path. It then verifies the resolved path stays within the base directory using `Path.startsWith()` on Path objects (not strings). If containment fails, an exception is thrown, preventing directory traversal.

## Behaviour changes
- **Exception type changed**: The method still declares `throws IOException`, which is correct; `toRealPath()` throws `IOException` if paths cannot be resolved or do not exist
- **New validation exception**: Added explicit check that throws `IllegalArgumentException` if the target path escapes the base directory, improving clarity of failure mode
- **Symlink resolution**: The code now follows symlinks, which is necessary for proper containment verification; this prevents symlink-based escapes
- **Base directory canonicalization**: `BASE_DIR.toRealPath()` is called during validation to ensure consistent path comparison; if `BASE_DIR` itself does not exist, `IOException` is thrown, which surfaces configuration errors appropriately
- **No breaking API changes**: The method signature and return type remain unchanged; the file read behavior is preserved for legitimate paths

## Verification
Compiled the fixed code with `javac`:
```
javac ReportFileReader.java
```
Result: Compilation successful with no errors. The code uses only standard Java NIO APIs (`java.nio.file.Path`, `java.nio.file.Files`, `java.io.IOException`) that are part of the Java standard library since Java 7, with `toRealPath()` available since Java 7.

## Assumptions
- **Assumption 1**: `BASE_DIR` represents a real filesystem directory that exists at runtime (or will be created before `readReport()` is called). If it does not exist, `toRealPath()` will throw `IOException`, which is the intended behavior to surface configuration issues.
- **Assumption 2**: Files to be read are expected to exist at the time `readReport()` is called. If a file does not exist, `toRealPath()` throws `NoSuchFileException` (subclass of `IOException`), which is appropriate for this use case.
