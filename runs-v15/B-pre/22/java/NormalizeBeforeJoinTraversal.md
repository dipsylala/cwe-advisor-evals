## Verdict

Exploitable. An attacker can supply an absolute path like `/etc/passwd` to read arbitrary files outside the base directory. The `Path.normalize()` call is textual-only and does not prevent absolute path traversal; `Path.resolve()` with an absolute argument replaces the base directory entirely rather than constraining the result to stay within it.

## Source

The source is the `userSuppliedPath` parameter (line 10), which is attacker-controlled.

## Fix

**Vulnerable code (line 10-15):**
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
    Path target = BASE_DIR.resolve(userSuppliedPath).toRealPath();
    Path canonicalBase = BASE_DIR.toRealPath();
    
    // Verify the resolved path is within the base directory
    if (!target.startsWith(canonicalBase)) {
        throw new IOException("Path traversal attempt detected");
    }
    
    return Files.readAllBytes(target);
}
```

## Explanation

The fix replaces `normalize()` with `toRealPath()`, which canonicalizes paths by resolving symlinks and relative references (`.`, `..`) to their absolute form. After canonicalization, `startsWith()` is used to verify that the resolved path stays within `BASE_DIR`. This prevents absolute path injection because `toRealPath()` converts any absolute path to its real form, and the containment check enforces that the result is a descendant of the base directory. Any attempt to traverse outside via `../` sequences or absolute paths will fail the validation and raise an exception before the file operation proceeds.

## Behaviour changes

**Addition of exception on path traversal:** The fixed code now raises `IOException` if the resolved path is outside `BASE_DIR`. The original code had no such guard and would read any file on the system. This is an intentional and necessary change to close the vulnerability.

**Switch from `normalize()` to `toRealPath()`:** The original used `normalize()`, which only rewrites the path string textually and leaves symlinks unresolved. The fix uses `toRealPath()`, which resolves symlinks and validates that the path can be accessed. This ensures the security check operates on the actual filesystem target, not a symbolic link that could bypass the check.

**Explicit containment validation:** The original code attempted implicit containment via `resolve()` alone, which is insufficient. The fix adds an explicit `startsWith()` check after canonicalization. This is necessary because `resolve()` with an absolute path argument replaces the base directory rather than constraining to it.

All differences trace to closing the path traversal weakness. The sink contract (`Files.readAllBytes()` returns `byte[]` and throws `IOException`) is preserved; the fix only adds an earlier exception when the input violates the containment policy.
