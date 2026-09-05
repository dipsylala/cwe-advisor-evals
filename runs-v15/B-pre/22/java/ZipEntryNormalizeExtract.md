## Verdict

Path Traversal via symlink - CONFIRMED. The vulnerability is not in the validation logic but in the canonicalization method. `Path.normalize()` removes `..` sequences textually without resolving symlinks; an attacker can craft a zip file containing entries that, when resolved against a destination directory containing symlinks, escape the intended extraction boundary.

## Source

`ZipEntry.getName()` from the input `ZipInputStream` (line 12, `zip.getNextEntry()`) is untrusted, attacker-controlled data.

## Fix

Replace `normalize()` with canonicalization that follows symlinks. For archive extraction where the target file does not exist yet, canonicalize the parent directory and reconstruct the full path using the real parent.

**Vulnerable code (line 13-18):**

```java
Path target = destination.resolve(entry.getName()).normalize();
if (!target.startsWith(destination)) {
    throw new IOException("entry escapes destination");
}

Files.copy(zip, target);
```

**Fixed code:**

```java
Path realDestination = destination.toRealPath();
Path target = realDestination.resolve(entry.getName());
Path targetParent = target.getParent();

// Create parent directories and canonicalize them
Files.createDirectories(targetParent);
Path realTargetParent = targetParent.toRealPath();

if (!realTargetParent.startsWith(realDestination)) {
    throw new IOException("entry escapes destination");
}

Path realTarget = realTargetParent.resolve(target.getFileName());
Files.copy(zip, realTarget);
```

## Explanation

The fix replaces textual path normalization with real path canonicalization that follows symlinks and resolves `.` and `..` to their actual targets. It canonicalizes the destination directory at the start with `toRealPath()`, which follows symlinks and raises an error if the path does not exist (the caller must ensure the destination directory exists before calling this method).

For each zip entry, the code now:
1. Resolves the entry name against the real destination
2. Creates parent directories as needed
3. Canonicalizes the parent directory with `toRealPath()`
4. Verifies the real parent is within the real destination
5. Reconstructs the target path using the canonicalized parent

This ensures that symlinks planted in the destination directory cannot redirect extraction outside the intended boundary. The check is performed on the real path after symlink resolution, eliminating the bypass.

## Behaviour changes

- **New exception**: `Files.createDirectories()` and `toRealPath()` throw `IOException` on failure. Existing callers expecting only the "entry escapes destination" exception will now see other I/O errors (e.g., permission denied, filesystem limit reached). Callers should already be catching `IOException` from `Files.copy()`.
- **Implicit file creation**: Parent directories are created if they do not exist. The original code would fail at `Files.copy()` if the parent didn't exist. The new code succeeds, which is the intended behaviour for extraction.
- **Destination must exist**: The `destination` parameter must be an existing directory for `toRealPath()` not to throw. This is a prerequisite the caller should already enforce; if not enforced, wrap the initial `toRealPath()` call in a try-catch and provide a clearer error message.
