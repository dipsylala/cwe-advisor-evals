## Verdict

Exploitable. CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), high confidence.

`extract()` already rejects classic `../` and absolute-path traversal correctly (`destination.resolve(entry.getName()).normalize()` followed by `Path.startsWith()` catches those cases). The gap is narrower but real: `Path.normalize()` is purely lexical - it never touches the filesystem - so it cannot detect a symbolic link sitting in an intermediate directory of the extraction target. If any path component between `destination` and the final entry name is a symlink pointing outside `destination` (planted by an earlier extraction, a prior process, or simply present on the host), the lexical check reports containment while `Files.copy` follows the real, symlink-resolved path and writes outside the intended root. `cwe/22/java/INDEX.md` calls this out directly: verify containment "after `toRealPath()` ... not after `normalize()`, which is the weaker option ... and which leaves a symlinked entry in place."

## Source

`entry.getName()` - the name of the current `ZipEntry`, read from the attacker-supplied archive via `zip.getNextEntry()` on the `ZipInputStream` parameter. Fully untrusted; nothing upstream of this method constrains it.

## Fix

Vulnerable code (`ZipExtractor.java`):

```java
public void extract(ZipInputStream zip, Path destination) throws IOException {
    ZipEntry entry;
    while ((entry = zip.getNextEntry()) != null) {
        Path target = destination.resolve(entry.getName()).normalize();
        if (!target.startsWith(destination)) {
            throw new IOException("entry escapes destination");
        }

        // Files.copy() follows any symlink in the path; normalize() above
        // never checked whether one exists, so it can write outside destination.
        Files.copy(zip, target);
    }
}
```

Fixed code:

```java
public void extract(ZipInputStream zip, Path destination) throws IOException {
    Path destinationReal = destination.toRealPath();
    ZipEntry entry;
    while ((entry = zip.getNextEntry()) != null) {
        Path target = destinationReal.resolve(entry.getName()).normalize();
        if (!target.startsWith(destinationReal)) {
            throw new IOException("entry escapes destination: " + entry.getName());
        }

        Path parent = entry.isDirectory() ? target : target.getParent();
        Files.createDirectories(parent);
        Path parentReal = parent.toRealPath();
        if (!parentReal.startsWith(destinationReal)) {
            throw new IOException("entry escapes destination via symlink: " + entry.getName());
        }

        if (entry.isDirectory()) {
            continue;
        }

        Path safeTarget = parentReal.resolve(target.getFileName());
        Files.copy(zip, safeTarget);
    }
}
```

## Explanation

The lexical `normalize()`/`startsWith()` check is kept as a cheap first-pass rejection of `../` sequences and absolute entry names before anything touches disk, but it is no longer the containment authority. `destination` is canonicalized once up front with `toRealPath()`, and for each entry the *parent* directory - not the not-yet-existing target file - is canonicalized with `toRealPath()` after being created, and re-checked with `startsWith()` against the real destination. This is the pattern the Java guidance prescribes for a write target that doesn't exist yet: `toRealPath()` requires the path to exist, so it is applied to the parent (which does, once created) rather than the target itself. Directory entries create their own directory and stop, so a later `toRealPath()` on that directory doesn't collide with a file write to the same name. The final copy path is rebuilt by appending the entry's single filename component (`target.getFileName()`) onto the *real* parent, so the bytes are written through the symlink-resolved path that was actually validated, rather than through the earlier lexical path that a planted symlink could redirect underneath it.

## Behaviour changes

- `destination` is now resolved with `toRealPath()` before the loop starts. New: throws `IOException` if `destination` does not exist (previously the method never touched `destination` itself, only derived paths from it). Reason: `toRealPath()` is required to establish the canonical root that later symlink checks compare against.
- Each entry's parent directory is now created with `Files.createDirectories()` before the file is written. New: the original code had no directory-creation logic and would throw `NoSuchFileException` from `Files.copy` for any entry inside a subdirectory that did not already exist. Reason: `toRealPath()` can only canonicalize a path that exists, so the parent must be created first to allow the real-path containment check on it.
- A second `IOException` (distinct message) is now thrown when a canonicalized parent directory resolves outside `destinationReal` via a symlink, in addition to the original lexical-escape check. Reason: this is the actual weakness being closed; the original single check only ever caught lexical `..`/absolute-path escapes.
- Directory entries (`entry.isDirectory()`) are now created as directories and skipped rather than passed to `Files.copy`. Reason: required once parent directories are pre-created - copying a directory entry's (empty) stream over a path that now exists as a directory would fail or corrupt the tree.
- The path actually passed to `Files.copy` is now `parentReal.resolve(target.getFileName())` instead of the original `target`. Reason: ensures the write goes through the validated, symlink-resolved parent rather than the pre-validation lexical path.
- `Files.copy` is still called with no `CopyOption`, preserving the original fail-if-exists behaviour on a duplicate entry name.
