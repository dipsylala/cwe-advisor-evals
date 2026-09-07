## Verdict

Exploitable

## Source

Untrusted user input: `request.getParameter("note")` at line 27

## Sink

Path validation and file access: `canonicalPath.startsWith(BASE_DIR)` at line 37 and file open at line 42

## Explanation

The vulnerability is a string-based path prefix check that fails to prevent access to sibling directories. The check `canonicalPath.startsWith(BASE_DIR)` where `BASE_DIR = "/app/uploads"` (without trailing separator) incorrectly accepts paths like `/app/uploads-secret/file.txt` because the string `/app/uploads-secret/file.txt` does start with the prefix `/app/uploads`. This allows an attacker to bypass the containment check by requesting a file with a path component that starts with the base directory name but diverges afterward.

The fix replaces string-based comparison with Java's `Path.startsWith(Path)` method, which is path-component-aware. The comparison now recognizes that `/app/uploads-secret` is a sibling directory, not a subdirectory of `/app/uploads`, and correctly rejects it. Additionally, the fix uses `Path.toRealPath()` to canonicalize both the base directory and the candidate path, properly resolving symbolic links and relative path components (`.` and `..`) before containment verification.

## Behaviour changes

1. **Path API migration**: Changed from `java.io.File` and `String` manipulation to `java.nio.file.Path`, which provides path-component-aware comparison. This is functionally equivalent for normal files but more robust for security comparisons.

2. **Canonicalization of base directory**: The original code used a string constant `BASE_DIR` directly in the comparison. The fixed code canonicalizes `BASE_DIR` to an absolute path using `toRealPath()`, ensuring both sides of the comparison are in canonical form. This eliminates any risk from relative paths or symlinks in the base directory itself.

3. **No other changes to method contract**: The method signature, error handling flow, content type, and file streaming logic remain identical. The IOException from `toRealPath()` is consistent with the original method signature which already throws `IOException`.

## Fixed Code

**Original (vulnerable):**
```java
File candidate = new File(BASE_DIR, noteName);
String canonicalPath = candidate.getCanonicalPath();

// Line 37: VULNERABLE - String comparison accepts sibling directories
if (!canonicalPath.startsWith(BASE_DIR)) {
    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to the requested note is denied");
    return;
}

File noteFile = new File(canonicalPath);
```

**Fixed:**
```java
import java.nio.file.Path;
import java.nio.file.Paths;

// In doGet method:
Path baseDir = Paths.get(BASE_DIR).toRealPath();
Path candidate = baseDir.resolve(noteName);
Path resolvedPath = candidate.toRealPath();

// Enforce containment using Path.startsWith(Path) for path-component-aware comparison
// This prevents sibling directory access like /app/uploads-secret
if (!resolvedPath.startsWith(baseDir)) {
    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to the requested note is denied");
    return;
}

File noteFile = resolvedPath.toFile();
```

Add imports to the file:
```java
import java.nio.file.Path;
import java.nio.file.Paths;
```

## Verification

Syntax verified with javac 26. Compilation against full classpath would require servlet API dependencies (javax.servlet), which are external to the core fix. The path-handling logic uses only standard Java libraries (`java.nio.file.Path`, `java.nio.file.Paths`) that are in the base Java module and require no additional dependencies.

The core logic change (string comparison → `Path.startsWith()`) is a standard Java API call documented in the JDK. All new names (`Path`, `Paths`, `toRealPath()`, `resolve()`, `startsWith()`) are part of the `java.nio.file` package available in Java 7 and later.
