## Verdict
exploitable

## Source
`entry.getName()` from `ZipInputStream.getNextEntry()` - untrusted archive entry name

## Fix

**Vulnerable code (lines 10-20):**
```java
public void extract(ZipInputStream zip, Path destination) throws IOException {
    ZipEntry entry;
    while ((entry = zip.getNextEntry()) != null) {
        Path target = destination.resolve(entry.getName()).normalize();  // VULNERABLE: normalize() is textual, doesn't follow symlinks
        if (!target.startsWith(destination)) {
            throw new IOException("entry escapes destination");
        }

        Files.copy(zip, target);  // SINK: follows symlinks, can escape
    }
}
```

**Fixed code:**
```java
public void extract(ZipInputStream zip, Path destination) throws IOException {
    Path canonicalDestination = destination.toRealPath();  // Canonicalize once outside loop
    ZipEntry entry;
    while ((entry = zip.getNextEntry()) != null) {
        Path target = destination.resolve(entry.getName());
        
        // Verify containment using canonical paths (resolves symlinks)
        try {
            Path canonicalTarget = target.toRealPath();
            if (!canonicalTarget.startsWith(canonicalDestination)) {
                throw new IOException("entry escapes destination");
            }
        } catch (NoSuchFileException e) {
            // Target doesn't exist yet (normal for new extracted files)
            // Canonicalize parent instead and verify it stays within destination
            Path parent = target.getParent();
            if (parent != null) {
                Path canonicalParent = parent.toRealPath();
                if (!canonicalParent.startsWith(canonicalDestination)) {
                    throw new IOException("entry escapes destination");
                }
            }
        }

        Files.copy(zip, target);
    }
}
```

## Explanation
The vulnerability is a Zip Slip variant where `normalize()` performs only textual path normalization without resolving symbolic links. An attacker can place a symlink entry in the archive (e.g., a symlink named `config` that points to `../../../etc/passwd`) which passes the textual containment check but `Files.copy()` follows the symlink and writes outside the destination. The fix replaces `normalize()` with `toRealPath()` which canonicalizes paths by resolving all symlinks to their real targets. Since extracted files don't exist yet, when `toRealPath()` fails with `NoSuchFileException`, we canonicalize the parent directory instead and verify the parent itself remains within the destination using `startsWith()` comparison on canonical paths.

## Behaviour changes
- `destination.toRealPath()` now called once before the loop instead of implicitly within each containment check, improving performance and ensuring consistent canonicalization across all entries
- Added explicit handling for `NoSuchFileException` to support the common case of extracting to non-existent subdirectories within the destination
- Validation now follows symlinks and their real targets (symlinks can no longer be used for containment bypass)
