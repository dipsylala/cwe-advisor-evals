## Verdict

exploitable

## Source

- **Source**: `userSuppliedPath` parameter (user-controlled input)
- **Sink**: `Files.readAllBytes(target)` at line 15
- **Data flow**: `userSuppliedPath` → `normalize()` → `resolve()` → `Files.readAllBytes()`

## Fix

**Vulnerable code:**
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
    
    // Verify the resolved path is within the base directory
    if (!target.startsWith(BASE_DIR.toRealPath())) {
        throw new IOException("Path traversal attempt detected: resolved path is outside the base directory");
    }
    
    return Files.readAllBytes(target);
}
```

## Explanation

The vulnerability exists because `Path.normalize()` is a textual operation that does not resolve symbolic links or prevent traversal sequences from escaping the intended directory. Input like `../../etc/passwd` passes through normalize unchanged and, when resolved against the base directory, can reference files outside it.

The fix replaces normalization with `toRealPath()`, which canonicalizes the path by resolving symbolic links and relative references (`.` and `..`) to their true absolute form. After resolving the user input against the base directory and canonicalizing, a containment check using `Path.startsWith()` verifies that the resolved path remains within the base directory hierarchy. If containment is violated, the request is rejected with an IOException. The containment check uses `Path` object comparison (not string comparison) to avoid sibling-directory bypass attacks like accepting `/app/uploads-backup` when `/app/uploads` is the intended base.

## Behaviour changes

**Exception handling**: The fixed code may throw `IOException` earlier—either from `toRealPath()` if the file does not exist, or from the containment check if traversal is detected. This is an intentional tightening of failure behaviour: reads of non-existent files now fail consistently at path validation rather than deferring to the file operation.

**No string conversion**: The fixed code keeps the path as a `Path` object throughout, eliminating the intermediate `.toString()` conversion. This preserves path semantics and enables use of path-aware comparison methods.

**No functional change to valid requests**: When `userSuppliedPath` refers to a file within the base directory, `toRealPath()` resolves it to the canonical form and the containment check passes, so `Files.readAllBytes()` receives the same (or symlink-dereferenced equivalent) path it would have received after the original normalization, assuming the path is safe.
