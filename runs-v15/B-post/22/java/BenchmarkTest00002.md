## Verdict

Exploitable

## Source

Line 61: Cookie value `BenchmarkTest00002` is extracted via `theCookie.getValue()` and URL-decoded with `URLDecoder.decode()`, stored in variable `param`. An attacker controls this value through HTTP request cookies.

## Fix

**Vulnerable code (line 71-74):**
```java
fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;

// SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened. Sink is the next statement.
fos = new java.io.FileOutputStream(fileName, false);
```

**Fixed code:**
```java
java.nio.file.Path baseDir = java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toRealPath();

// Verify the filename is a single path component with no separators
java.nio.file.Path filenamePath = java.nio.file.Paths.get(param);
if (!filenamePath.getFileName().toString().equals(param)) {
    throw new java.io.IOException("Invalid filename: contains path separators or traversal sequences");
}

// Resolve against base and canonicalize the parent directory
java.nio.file.Path resolvedPath = baseDir.resolve(param);
java.nio.file.Path parentDir = resolvedPath.getParent().toRealPath();

// Verify the resolved path stays within the base directory
if (!parentDir.startsWith(baseDir)) {
    throw new java.io.IOException("Path traversal attempt detected");
}

fileName = resolvedPath.toString();
fos = new java.io.FileOutputStream(fileName, false);
```

## Explanation

The fix validates the user-supplied filename before constructing the file path. It canonicalizes the base directory using `toRealPath()` to resolve symlinks and relative paths to absolute form. Before opening the file, it verifies that the supplied filename is a single path component (rejecting `../`, `./`, absolute paths, and any other traversal sequences) by checking that `Paths.get(param).getFileName()` equals `param`. It then resolves the filename against the base directory and canonicalizes the parent directory. Finally, it verifies that the parent of the resolved path is contained within the base directory using `Path.startsWith(Path)`, which performs path-component-aware comparison and prevents sibling directory escapes. This ensures that even with encoding tricks, symlink attacks, or relative-path tricks, the attacker cannot access files outside the intended base directory.

## Behaviour changes

The fix adds path validation that throws `IOException` if traversal sequences are detected, which is caught by the existing catch block. The resolved absolute path is used instead of string concatenation, eliminating the vulnerability while maintaining the same exception contract and file-opening semantics as the original code.
