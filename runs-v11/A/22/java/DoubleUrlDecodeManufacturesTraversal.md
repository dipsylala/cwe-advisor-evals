## Verdict
CONFIRMED

## Source
```java
// Line 38: Decode user-controlled filename
String filename = URLDecoder.decode(rawFilename, "UTF-8");

// Line 40-42: Incomplete check—only blocks ".." but misses absolute paths
if (filename.contains("..")) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
    return;
}

// Line 46: SINK—absolute path in second argument bypasses parent directory
File target = new File(ATTACHMENTS_DIR, filename);
```

## Fix
Replace lines 36–46 with path normalization and containment verification:

```java
String filename = URLDecoder.decode(rawFilename, "UTF-8");

// Resolve the requested path against the attachments directory
Path attachmentsPath = Paths.get(ATTACHMENTS_DIR).toAbsolutePath();
Path requestedPath = attachmentsPath.resolve(filename).normalize();

// Reject if the resolved path escapes the attachments directory
if (!requestedPath.startsWith(attachmentsPath)) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
    return;
}

File target = requestedPath.toFile();
```

Add this import at the top of the file:
```java
import java.nio.file.Path;
import java.nio.file.Paths;
```

## Explanation
The original code is vulnerable because `new File(parent, child)` ignores the parent argument if `child` is an absolute path (e.g., `/etc/passwd`). The `..` check only blocks one traversal pattern and misses both absolute paths and other escape sequences.

`Path.resolve()` correctly merges the parent and child. `normalize()` collapses `.` and `..` sequences into their canonical form. Finally, `startsWith()` verifies the resolved path remains within `ATTACHMENTS_DIR`. Together, these operations close all path traversal vectors: absolute paths, relative traversals, and double-encoded payloads.
