## Verdict

Exploitable.

## Source

The vulnerability originates in the request parameter `noteName = request.getParameter("note")` (line 27), which is user-supplied and attacker-controlled. This value is passed through a File constructor without sufficient containment validation.

## Fix

**Vulnerable code (line 33-40):**
```java
File candidate = new File(BASE_DIR, noteName);
String canonicalPath = candidate.getCanonicalPath();

// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
if (!canonicalPath.startsWith(BASE_DIR)) {
    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to the requested note is denied");
    return;
}
```

**Fixed code:**
```java
File candidate = new File(BASE_DIR, noteName);
String canonicalPath = candidate.getCanonicalPath();

// Use Path.startsWith(Path) for path-component-aware comparison
Path candidatePath = Paths.get(canonicalPath);
Path basePath = Paths.get(BASE_DIR).toAbsolutePath();

if (!candidatePath.startsWith(basePath)) {
    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to the requested note is denied");
    return;
}
```

**Required imports:**
Add `import java.nio.file.Path;` and `import java.nio.file.Paths;`

## Explanation

The vulnerability is a sibling-directory bypass of the path containment check. The original code uses a string prefix match (`canonicalPath.startsWith(BASE_DIR)`) to verify the canonical path is within `/app/uploads`. However, this allows paths like `/app/uploads-secret` to pass the check because the string `/app/uploads-secret` starts with the string `/app/uploads`. The fix uses `java.nio.file.Path` objects and the `Path.startsWith(Path)` method, which performs path-component-aware comparison instead of string matching. This ensures that only paths that are truly under the base directory (as path components, not just string prefixes) are accepted. The canonical path is converted to a Path object and compared against the base directory path, which is also converted to an absolute Path object to ensure consistent comparison.

## Behaviour changes

None. The fix preserves the original validation logic, control flow, and failure behavior. The containment check still rejects attempts to access files outside the base directory and returns the same HTTP 403 Forbidden error response. The only change is the mechanism of comparison: from string prefix matching to proper path-component comparison.
