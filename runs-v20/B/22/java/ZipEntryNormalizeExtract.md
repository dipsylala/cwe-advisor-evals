## Verdict

Confirmed - exploitable. `ZipExtractor.extract` performs the standard textual Zip Slip check (`normalize()` + `startsWith()`), but that check alone does not follow symbolic links. If the extraction destination (or a subdirectory an earlier entry created) contains a symlink pointing outside the destination tree, an entry whose name resolves underneath that symlinked directory passes the string-based containment check yet is written outside the intended root when `Files.copy` follows the link.

## Source

`entry.getName()` from `java.util.zip.ZipEntry`, read via `zip.getNextEntry()` on the `ZipInputStream` parameter - the archive is attacker-controlled input.

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
        Path destinationReal = destination.toRealPath();
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            Path target = destination.resolve(entry.getName()).normalize();
            if (!target.startsWith(destination)) {
                throw new IOException("entry escapes destination");
            }

            Path parent = target.getParent();
            Files.createDirectories(parent);
            Path parentReal = parent.toRealPath();
            if (!parentReal.startsWith(destinationReal)) {
                throw new IOException("entry escapes destination");
            }

            Files.copy(zip, target);
        }
    }
}
```

## Explanation

The existing `destination.resolve(entry.getName()).normalize()` + `startsWith(destination)` check is the correct first line of defence - it rejects `../` and absolute entry names textually - but `normalize()` is purely lexical and never touches the filesystem, so it cannot detect that a path component is actually a symlink pointing elsewhere. The fix adds the second step the CWE-22 Java guidance prescribes for archive extraction: create the entry's parent directory (needed because the target does not exist yet, so `toRealPath()` cannot be called on it directly), then resolve that parent with `toRealPath()` - which does follow symlinks - and verify the resolved real path is still contained within the destination's own real path (`destinationReal`, canonicalized once up front so both sides of the comparison are resolved the same way). If an earlier entry (or a pre-existing directory) planted a symlink that would redirect the write outside the destination, the real-path check catches it and the entry is rejected before `Files.copy` runs. `Files.createDirectories` was added only because it is a prerequisite for calling `toRealPath()` on the parent; it also incidentally makes nested entries such as `sub/dir/file.txt` extract correctly, which the original code could not do at all since it never created intermediate directories. `Files.copy(zip, target)` itself is unchanged: no copy options are added, so a pre-existing target still causes it to throw `FileAlreadyExistsException` exactly as before, and its return value continues to be discarded.

## Behaviour changes

- `destination` must exist when `extract` is called (`destination.toRealPath()` now runs once before the loop and throws `IOException` if it does not). The original code never required this until the first `Files.copy`.
- Nested entries (e.g. `sub/dir/file.txt`) now have their parent directories created automatically via `Files.createDirectories`; previously such entries would fail with `NoSuchFileException` since no parent directory ever existed.
- An entry whose resolved parent directory is reached through a symlink leading outside `destination` is now rejected with `IOException("entry escapes destination")` even though it previously passed the textual containment check. This is the intended security tightening and only affects malicious or symlink-crossing archives.
- No change to the success-path return value, the copy options used by `Files.copy`, or the handling of a target that already exists.

**Check performed:** compiled the fixed file with `javac` (JDK 26) from a scratch directory outside the repository - `javac -d out cases/path/ZipExtractor.java` - with no errors or warnings. Every name introduced by the fix (`Path.getParent()`, `Files.createDirectories(Path)`, `Path.toRealPath()`, `Path.startsWith(Path)`) is a standard `java.nio.file` API already available via the file's existing imports.
