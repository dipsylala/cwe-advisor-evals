## Verdict

Exploitable.

## Source

User-supplied filename via `request.getParameter("file")` at line 30. The servlet container has already percent-decoded the parameter once; a second decoding at line 38 manufactures traversal sequences from inert encoded literals (`%252e%252e%252f` becomes `../` after the second decode).

## Fix

**Vulnerable code (lines 28–46):**

```java
// request.getParameter() has already been percent-decoded once by the
// servlet container, so rawFilename is already plain text at this point.
String rawFilename = request.getParameter("file");
if (rawFilename == null || rawFilename.isEmpty()) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "file parameter is required");
    return;
}

// Some older clients double-encode the filename, so decode again to
// normalize it before validating and building the path.
String filename = URLDecoder.decode(rawFilename, "UTF-8");

if (filename.contains("..")) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
    return;
}

// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
File target = new File(ATTACHMENTS_DIR, filename);
```

**Fixed code (lines 28–58):**

```java
// request.getParameter() has already been percent-decoded once by the
// servlet container, so filename is already plain text at this point.
String filename = request.getParameter("file");
if (filename == null || filename.isEmpty()) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "file parameter is required");
    return;
}

// Reject paths containing traversal sequences or path separators
if (filename.contains("..") || filename.contains(File.separator)) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
    return;
}

// Canonicalize the requested file path and verify it stays within ATTACHMENTS_DIR
File target = new File(ATTACHMENTS_DIR, filename);
File baseDir = new File(ATTACHMENTS_DIR);

String canonicalTarget = target.getCanonicalPath();
String canonicalBase = baseDir.getCanonicalPath() + File.separator;

if (!canonicalTarget.startsWith(canonicalBase)) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
    return;
}

// Use the canonicalized path for file access
File canonicalFile = new File(canonicalTarget);

response.setContentType("application/octet-stream");
response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

try (InputStream in = new FileInputStream(canonicalFile);
     OutputStream out = response.getOutputStream()) {
    byte[] buffer = new byte[8192];
    int read;
    while ((read = in.read(buffer)) != -1) {
        out.write(buffer, 0, read);
    }
}
```

## Explanation

The vulnerability arises from double-decoding and incomplete path validation. The servlet container percent-decodes the `file` parameter once, but line 38's `URLDecoder.decode()` call decodes again—turning inert literals like `%2e%2e%2f` into the traversal sequence `../`. The `contains("..")` check on line 40 is insufficient: it does not catch absolute paths (e.g., `/etc/passwd`), symlinks pointing outside the base directory, or other path-resolution tricks. 

The fix removes the redundant second decode (per the principle that frameworks already decode once), rejects any filename containing path separators or traversal markers, and crucially adds canonicalization using `File.getCanonicalPath()`. Canonicalization resolves symbolic links and relative path components (`.`, `..`) to their absolute form before the containment check. The `startsWith()` comparison on separator-terminated base paths ensures the resolved file is strictly inside `ATTACHMENTS_DIR`, even if the attacker supplies a symlink or relative path. Finally, the canonicalized path is used for the file operation, preventing a TOCTOU race between validation and file access.

## Behaviour changes

- Removed the second `URLDecoder.decode()` call and its comment about "older clients double-encoding"—frameworks handle all necessary decoding, and a second pass manufactures vulnerabilities rather than fixing them.
- Enhanced validation to reject filenames containing `File.separator` (in addition to `..`), catching absolute paths on all platforms.
- Added two `File.getCanonicalPath()` calls to resolve the target and base directory to absolute canonical form, following symbolic links.
- Added a containment check comparing the canonicalized target path against the canonicalized base directory (with separator appended) using `startsWith()` on the string representation—this prevents false matches (e.g., `/app/uploads-backup` would fail if the base were `/app/uploads` without the separator).
- Changed `FileInputStream(target)` to `FileInputStream(canonicalFile)` to use the validated, canonicalized path rather than the raw user-supplied input.

All other behavior—error responses, content type, streaming, exception handling—remains unchanged.

