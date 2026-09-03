## Verdict

exploitable

## Source

The vulnerability originates from the `userSuppliedPath` parameter at line 10, which accepts attacker-controlled input. The parameter flows through path normalization and resolution at lines 11–12 to the file read sink at line 15 (`Files.readAllBytes(target)`), where no containment verification occurs.

## Fix

**Vulnerable code (line 10–16):**
```java
public byte[] readReport(String userSuppliedPath) throws IOException {
    String cleaned = Path.of(userSuppliedPath).normalize().toString();
    Path target = BASE_DIR.resolve(cleaned);

    // SAST FINDING: CWE-22 (Path Traversal) reported here. Sink is the next statement.
    return Files.readAllBytes(target);
}
```

**Fixed code:**
```java
public byte[] readReport(String userSuppliedPath) throws IOException {
    // Reject absolute paths that would bypass the base directory
    if (Paths.get(userSuppliedPath).isAbsolute()) {
        throw new SecurityException("Absolute paths are not allowed");
    }
    
    // Resolve against base directory and canonicalize (toRealPath follows symlinks and resolves ..)
    Path resolved = BASE_DIR.resolve(userSuppliedPath).toRealPath();
    
    // Verify the resolved path stays within the base directory
    if (!resolved.startsWith(BASE_DIR.toRealPath())) {
        throw new SecurityException("Path traversal detected");
    }
    
    return Files.readAllBytes(resolved);
}
```

**Required import addition:**
```java
import java.nio.file.Paths;
```

## Explanation

The original code uses `Path.normalize()` which only performs textual normalization of the string—it does not follow symlinks and does not enforce containment within the base directory. This creates three exploitable gaps:

1. **Symlink bypass**: A symlink within the base directory can point to any location on the filesystem, bypassing the attempted directory confinement.
2. **Traversal escape**: Paths like `../../../etc/passwd` are resolved against the base directory and can escape it (e.g., `/var/app-data/reports/../etc/passwd` normalizes to `/var/app-data/etc/passwd`, outside the intended `reports/` subtree).
3. **Missing containment check**: No verification ensures the final path stays within the base directory.

The fix replaces `normalize()` with `toRealPath()`, which canonicalizes the path by following symlinks and resolving relative components (`..`, `.`), and adds a containment check using `Path.startsWith(Path)` to verify the canonical path stays within the base directory. Absolute paths are also rejected because `Path.resolve()` ignores the base when given an absolute argument.

## Behaviour changes

- **Added: SecurityException for absolute paths** — Requests containing absolute paths now throw SecurityException instead of silently passing through. Reason: Defend against `Path.resolve()` semantics, which ignore the base path when the argument is absolute.
- **Added: SecurityException for paths outside base** — Any path that resolves outside BASE_DIR throws SecurityException. Reason: Enforce mandatory containment verification.
- **Changed: toRealPath() instead of normalize()** — The path is now canonicalized via `toRealPath()`, which follows symlinks and eliminates relative components, rather than via textual normalization. Reason: Close the symlink-based escape vector and ensure canonical form for containment comparison.
- **Changed: Containment check via Path.startsWith()** — Uses path-component-aware comparison instead of string prefix matching. Reason: Prevent false positives like `/app/uploads` matching a base of `/app/upload`.
- **File existence requirement** — `toRealPath()` throws IOException if the target does not exist. This is consistent with the original method's signature and behavior (Files.readAllBytes also throws if the file does not exist). No behaviour change to callers that expect an exception on missing files.
- **Added: Paths import** — The code now imports `java.nio.file.Paths` for `Paths.get()` to test if input is absolute. No runtime cost beyond the absolute-path check itself.
