## Verdict

Confirmed. The extraction loop derives the write target from the zip entry name and guards it with a purely lexical check (`normalize()` + `Path.startsWith`), which never consults the filesystem. If any path component the write actually traverses is a symbolic link — for example an intermediate directory under `destination` that a symlink has been substituted for, whether left over from a prior extraction into a reused/shared destination or planted by another actor with write access to that tree — the OS resolves the link at the moment `Files.copy` performs the write and lands outside `destination`, even though the lexical check reported the target as contained. `Path.normalize()` only rewrites `.` and `..` segments in the string; it does not resolve symlinks, so it cannot detect this.

## Source

Untrusted input: `entry.getName()`, the file name embedded in each `ZipEntry` read from `zip` (`ZipInputStream`) — fully attacker-controlled by whoever supplies the archive passed into `extract()`.

Sink: `Files.copy(zip, target)` (line 18), which writes the entry's bytes to the filesystem path derived from that name.

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
        Files.createDirectories(destination);
        Path destinationReal = destination.toRealPath();

        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            Path target = destinationReal.resolve(entry.getName()).normalize();
            if (!target.startsWith(destinationReal)) {
                throw new IOException("entry escapes destination: " + entry.getName());
            }

            if (entry.isDirectory()) {
                Files.createDirectories(target);
                continue;
            }

            Path parent = target.getParent();
            Files.createDirectories(parent);

            // Re-resolve symlinks after creating the parent chain: normalize() above is
            // purely lexical, so a symlink sitting anywhere in that chain (left over from
            // a previous extraction, or planted by another writer with access to
            // `destination`) would let the lexical check pass while the actual write
            // lands outside destination. toRealPath() follows links and lets us verify
            // the real write location before any bytes are copied.
            Path parentReal = parent.toRealPath();
            if (!parentReal.startsWith(destinationReal)) {
                throw new IOException("entry escapes destination via symlink: " + entry.getName());
            }

            Files.copy(zip, target);
        }
    }
}
```

## Explanation

`destination.resolve(entry.getName()).normalize()` followed by `target.startsWith(destination)` is the standard Zip Slip defense and it does correctly reject direct `../` traversal and absolute-path entries, because `Path.startsWith` compares path components rather than raw strings. What it cannot catch is indirection through the filesystem itself: `normalize()` is a string-level operation on the path's name elements and never touches disk, so if a directory the resolved path passes through is actually a symbolic link, the lexical check and the real write location diverge. A `destination` directory that is reused across extractions (a common pattern for upload/staging directories) or that any other process can write into is exactly the case where such a link can exist by the time this code runs.

The fix keeps the existing lexical guard but adds a filesystem-grounded one: it canonicalizes `destination` once with `toRealPath()` (which requires the directory to exist, hence the added `createDirectories` call), resolves each entry against that real path, and — for regular-file entries — re-derives the real path of the immediate parent directory *after* creating it and checks that it still falls under the canonical destination before any bytes are copied. Directory entries are now created as directories via `createDirectories` rather than falling through to `Files.copy`, which also fixes the pre-existing failure where a directory entry or any nested entry under it would otherwise error because no parent directories were ever created. `Files.copy(zip, target)` is left without `REPLACE_EXISTING`, matching the original behavior of refusing to overwrite a file that already sits at the target path.
