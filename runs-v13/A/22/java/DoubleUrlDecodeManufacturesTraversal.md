## Verdict

The code is vulnerable to path traversal because it checks for ".." but does not validate that the resolved file path stays within the intended directory. An attacker can use absolute paths or path separators to escape the attachment directory.

## Source

Line 46 in `AttachmentDownloadServlet.java`:
```
File target = new File(ATTACHMENTS_DIR, filename);
```

The vulnerability exists because:
1. The ".." check on line 40 only detects literal ".." sequences
2. It does not prevent absolute paths (e.g., `/etc/passwd`)
3. It does not prevent path separators (`/`) that allow breaking out of ATTACHMENTS_DIR
4. An attacker can send double-encoded input like `%252Fetc%252Fpasswd` which after two decodes becomes `/etc/passwd`, bypassing the ".." check and resolving to an arbitrary file

## Fix

Replace the vulnerable path construction with canonical path validation:

```java
// Obtain canonical paths to resolve symlinks and remove . and .. references
File base = new File(ATTACHMENTS_DIR).getCanonicalFile();
File target = new File(base, filename).getCanonicalFile();

// Verify the resolved target path is within the base directory
if (!target.getAbsolutePath().startsWith(base.getAbsolutePath() + File.separator)) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
    return;
}

// Now safe to use target for file operations
```

Alternatively, using NIO APIs:

```java
Path basePath = Paths.get(ATTACHMENTS_DIR).toRealPath();
Path targetPath = basePath.resolve(filename).toRealPath();

// Verify the resolved target is within the base directory
if (!targetPath.startsWith(basePath)) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
    return;
}

// Now safe to use targetPath for file operations
```

## Explanation

The original code's ".." check is insufficient because:
- Absolute paths like `/etc/passwd` bypass the check since they contain no ".."
- Path separators in the filename allow constructing paths outside the attachment directory
- Double URL encoding bypasses simple string checks by deferring the traversal sequence until after decoding

The fix uses either `getCanonicalFile()` (Java IO) or `toRealPath()` (NIO) to:
1. Resolve the full absolute path including all symlinks
2. Normalize away any remaining ".." or "." references
3. Verify the final resolved path stays within the intended base directory using `startsWith()`

Only after this validation is the file safe to read from the resolved path.
