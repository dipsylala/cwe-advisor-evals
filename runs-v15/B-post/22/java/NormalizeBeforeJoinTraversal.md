## Verdict

Exploitable

## Source

`userSuppliedPath` parameter in the `readReport(String)` method signature.

## Fix

**Vulnerable code:**
```java
String cleaned = Path.of(userSuppliedPath).normalize().toString();
Path target = BASE_DIR.resolve(cleaned);

// SAST FINDING: CWE-22 (Path Traversal) reported here. Sink is the next statement.
return Files.readAllBytes(target);
```

**Fixed code:**
```java
Path realBase = BASE_DIR.toRealPath();
Path candidate = realBase.resolve(userSuppliedPath).toRealPath();
if (!candidate.startsWith(realBase)) {
    throw new IOException("Path traversal detected");
}

return Files.readAllBytes(candidate);
```

## Explanation

The original code uses `Path.normalize()`, which is a textual operation that removes `..` sequences from the path string but does not resolve symbolic links. An attacker can create a symbolic link inside the base directory (e.g., `/var/app-data/reports/link -> /etc/passwd`) and provide that link name as input. The `normalize()` call leaves the symlink intact, `resolve()` produces a path pointing to the symlink, and `Files.readAllBytes()` follows it to read a file outside the intended base directory.

The fix replaces textual normalization with `Path.toRealPath()`, which follows all symbolic links and returns the actual canonical absolute path. It then validates that the canonical target path is contained within the canonical base directory using `Path.startsWith()`, a path-component-aware comparison. Only paths that pass this containment check are read. This eliminates the traversal by detecting and rejecting any attempts to escape the base directory through symlinks, `..` sequences, or absolute path injection.

## Behaviour changes

- **Exception type change on validation failure**: The original code reaches the sink with any path that resolves against `BASE_DIR`. The fixed code throws `IOException` with message "Path traversal detected" if the final canonical path is not within the base directory. Callers expecting to handle `IOException` will catch this; code that does not catch exceptions will propagate the error up the call stack.

- **File existence requirement**: `Path.toRealPath()` requires the path to exist and be readable to obtain its canonical form. The original code would defer existence checking to `Files.readAllBytes()`, which throws `FileNotFoundException` if the file does not exist. The fixed code now throws `NoSuchFileException` (a subclass of `IOException`) earlier, from the `toRealPath()` call. Since both exceptions are subtypes of `IOException` and the method signature declares `throws IOException`, this is compatible behavior, but the specific timing and exception subtype change.

- **Performance**: The fix calls `toRealPath()` twice (once on the base directory, once on the candidate), which may involve filesystem traversal and I/O. This is a negligible cost for file I/O operations but is present.
