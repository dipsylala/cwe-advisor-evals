## Verdict

Confirmed. `readReport` lets a caller escape `/var/app-data/reports` and read an arbitrary file on the filesystem.

## Source

`userSuppliedPath`, the parameter to `ReportFileReader.readReport(String userSuppliedPath)`.

## Fix

### File: ReportFileReader.java

```java
package cases.pathtraversal;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ReportFileReader {
    private static final Path BASE_DIR = Path.of("/var/app-data/reports").toAbsolutePath().normalize();

    public byte[] readReport(String userSuppliedPath) throws IOException {
        Path target = BASE_DIR.resolve(userSuppliedPath).normalize();

        if (!target.equals(BASE_DIR) && !target.startsWith(BASE_DIR)) {
            throw new SecurityException("Resolved path escapes the reports directory: " + userSuppliedPath);
        }

        // SAST FINDING: CWE-22 (Path Traversal) reported here. Sink is the next statement.
        return Files.readAllBytes(target);
    }
}
```

## Explanation

The original code normalizes `userSuppliedPath` in isolation, before it is ever joined to `BASE_DIR`: `Path.of("../../etc/passwd").normalize()` has nothing to cancel the leading `..` segments against, so they survive normalization unchanged. `BASE_DIR.resolve(cleaned)` then walks those `..` segments upward from `/var/app-data/reports`, landing outside it. Worse, if `userSuppliedPath` is itself absolute (e.g. `/etc/passwd`), `Path.resolve()` on an absolute argument returns that argument verbatim, discarding `BASE_DIR` entirely regardless of what normalization was done first.

The fix reorders the operations so containment can actually be checked: resolve the untrusted segment against the base directory first, then normalize the combined result, then confirm the normalized target is still `BASE_DIR` or a descendant of it via `Path.startsWith`. `BASE_DIR` itself is pre-normalized and made absolute once, in the field initializer, so the comparison is between two normalized, absolute paths rather than a normalized target against a possibly-relative base (which would let a `startsWith` check pass or fail on the wrong basis). If the resolved-and-normalized target falls outside `BASE_DIR` — whether via `..` traversal or an absolute override — the method throws instead of touching the filesystem, so `Files.readAllBytes` only ever runs against a path inside the reports directory.
