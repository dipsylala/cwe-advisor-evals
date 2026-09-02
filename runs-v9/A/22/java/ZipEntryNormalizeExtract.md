## Verdict

Confirmed. `ZipExtractor.extract()` already applies a `resolve().normalize()` + `Path.startsWith()` guard, which correctly blocks the classic `../` traversal and absolute-path forms of Zip Slip (and, because it's a `Path`-based comparison rather than a string-prefix comparison, it isn't fooled by sibling-directory names like `destination-evil`). However, the guard only validates the *lexical* path — it never resolves the filesystem-level target before writing to it. `Files.copy(zip, target)` on line 18 opens `target` for writing without checking whether that path (or one of its parent directories) is already a symbolic link. If an attacker can get a symlink planted anywhere under `destination` before or during extraction — e.g. one archive entry that a permissive zip library materializes as a link, a shared/reused extraction directory, or a TOCTOU window between the check and the write — a later entry whose *name* lexically resolves inside `destination` can still have its bytes written through that link to an arbitrary filesystem location outside `destination`. The entry-name validation and the actual write are also not atomic with respect to that link. Additionally, the method never creates parent directories or special-cases directory entries, so any legitimate nested-path zip throws before the security-relevant code path is even reached in practice.

## Source

`entry.getName()`, read from the caller-supplied `ZipInputStream zip` via `zip.getNextEntry()` — the entry name is attacker-controlled content taken directly from the bytes of whatever zip archive is being extracted (e.g. an uploaded file), and flows unresolved into the filesystem write at `Files.copy(zip, target)`.

## Fix

```java
package cases.path;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ZipExtractor {
    public void extract(ZipInputStream zip, Path destination) throws IOException {
        Path destRoot = destination.toAbsolutePath().normalize();
        Files.createDirectories(destRoot);

        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            Path target = destRoot.resolve(entry.getName()).normalize();
            if (!target.equals(destRoot) && !target.startsWith(destRoot)) {
                throw new IOException("entry escapes destination: " + entry.getName());
            }

            if (entry.isDirectory()) {
                Files.createDirectories(target);
                continue;
            }

            Path parent = target.getParent();
            Files.createDirectories(parent);

            // Re-resolve through the filesystem (not just lexically) so a symlink
            // anywhere in the parent chain can't redirect the write outside destRoot.
            Path realParent = parent.toRealPath();
            if (!realParent.equals(destRoot) && !realParent.startsWith(destRoot)) {
                throw new IOException("entry parent escapes destination via link: " + entry.getName());
            }
            if (Files.isSymbolicLink(target)) {
                throw new IOException("refusing to overwrite existing link: " + entry.getName());
            }

            Files.copy(zip, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
```

## Explanation

The fix keeps the existing `resolve().normalize().startsWith()` check — it is the right first line of defense and should stay — but adds two things it was missing:

- **Filesystem-level (real-path) verification, not just lexical verification.** `normalize()` only collapses `.`/`..` segments as text; it never touches the disk, so it cannot notice that one of the already-created parent directories is a symlink pointing outside `destRoot`. Calling `parent.toRealPath()` after the directories exist resolves every symlink in the chain, and re-checking that result against `destRoot` closes the gap where a planted link could redirect a lexically-valid entry name to a write outside the destination.
- **An explicit symlink check on `target` itself**, and using `Files.copy(InputStream, Path, CopyOption...)` deliberately rather than any variant that would silently follow an existing link. If `target` already exists as a symlink, the code refuses to write through it instead of following it.

Both checks run immediately before the write, minimizing (though not eliminating) the TOCTOU window between validation and `Files.copy`.

Also fixed, as prerequisites for the security check to even be reachable on realistic archives: `destination` is resolved once via `toAbsolutePath().normalize()` so the comparison root is well-defined regardless of how the caller constructed the `Path`; directory entries are handled with `Files.createDirectories` instead of falling into the file-copy branch; and parent directories for nested file entries are created before the copy, so legitimate nested zip layouts no longer throw before extraction completes.
