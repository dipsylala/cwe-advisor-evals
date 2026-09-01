## Verdict

Path traversal vulnerability confirmed. The code attempts validation via `normalize()` and `startsWith()`, but this approach is insufficient and can be bypassed.

## Source

The vulnerable flow spans lines 13-18:

```java
Path target = destination.resolve(entry.getName()).normalize();
if (!target.startsWith(destination)) {
    throw new IOException("entry escapes destination");
}
Files.copy(zip, target);
```

The `destination` parameter is never normalized before the `startsWith()` comparison. Additionally, the code does not reject absolute paths in entry names, which `Path.resolve()` will apply before normalization.

## Fix

Normalize the destination upfront and reject absolute path entries:

```java
public void extract(ZipInputStream zip, Path destination) throws IOException {
    Path base = destination.normalize();
    ZipEntry entry;
    while ((entry = zip.getNextEntry()) != null) {
        String name = entry.getName();
        
        // Reject absolute paths
        if (new File(name).isAbsolute()) {
            throw new IOException("entry has absolute path");
        }
        
        Path target = base.resolve(name).normalize();
        if (!target.startsWith(base)) {
            throw new IOException("entry escapes destination");
        }

        Files.copy(zip, target);
    }
}
```

## Explanation

The original code has two weaknesses:

1. **Unnormalized destination**: The `destination` parameter is passed directly into `startsWith()` without normalization. If `destination` contains `.` or `..` components, the lexical comparison may fail to detect escapes. For example, if `destination` is `extract/./` and `target` normalizes to `extract/file`, the `startsWith()` check may fail.

2. **Absolute paths bypass resolve**: If an entry name starts with `/` (or a drive letter on Windows), `Path.resolve()` replaces the entire path rather than appending. The subsequent `normalize()` does not reverse this. For example, `base.resolve("/etc/passwd")` yields an absolute path outside the destination.

The fix normalizes `destination` once at the start of extraction and explicitly rejects entries with absolute paths before attempting extraction. This ensures the destination is always in canonical form for comparison, and entry names are constrained to relative paths within the destination directory.

