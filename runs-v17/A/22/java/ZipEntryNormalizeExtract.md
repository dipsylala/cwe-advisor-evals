## Verdict

VULNERABLE. The `destination` parameter is not normalized before the `startsWith()` containment check, allowing a crafted destination path containing redundant elements to bypass path traversal protection.

## Source

**File:** ZipExtractor.java  
**Line:** 18  
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

The vulnerability occurs at line 18 where `Files.copy(zip, target)` writes to a target path that has been validated using a non-normalized destination reference. The check on line 14 compares the normalized `target` against an unnormalized `destination`, creating a time-of-check mismatch that permits path traversal if the destination path itself contains non-canonical elements like `..`, `.`, or redundant separators.

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
        Path normalizedDestination = destination.toAbsolutePath().normalize();
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            Path target = normalizedDestination.resolve(entry.getName()).normalize();
            if (!target.startsWith(normalizedDestination)) {
                throw new IOException("entry escapes destination");
            }

            Files.copy(zip, target);
        }
    }
}
```

## Explanation

**Root Cause:**  
The original code performed path traversal validation by comparing a normalized `target` path against an unnormalized `destination` parameter. This creates a logical inconsistency: if `destination` itself contains non-canonical path elements (e.g., `/extract/..`, relative paths, or redundant separators), the `startsWith()` comparison operates on different canonical forms and can produce incorrect results.

**Fix Mechanism:**  
The corrected code:
1. Normalizes `destination` to its absolute, canonical form once at the start of extraction using `destination.toAbsolutePath().normalize()`
2. Uses the normalized destination for all `resolve()` calls and the `startsWith()` check
3. Ensures that both the target path and the destination reference are in the same canonical form, making the containment check logically sound

**Defense Depth:**
- `toAbsolutePath()` converts relative paths to absolute, preventing escape via relative traversal
- `normalize()` removes all `.` and `..` components, eliminating directory traversal attempts
- `startsWith()` on normalized paths reliably detects when a resolved entry escapes the extraction directory
- Resolving against the normalized destination ensures all extracted files are consistently bounded
