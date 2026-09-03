## Verdict

Exploitable.

## Source

Line 30: `request.getParameter("file")` returns an attacker-controlled filename. The servlet container has already percent-decoded the request parameter once, so the value arriving here is plain text (e.g., `../etc/passwd` if the attacker sent `%2e%2e%2fpasswd`).

## Sink

Line 46: `new File(ATTACHMENTS_DIR, filename)` constructs a path from the decoded filename without canonicalization or containment validation. Line 51 then opens the file with `new FileInputStream(target)`.

## Data Flow

1. **Vulnerability trigger**: Line 38 applies `URLDecoder.decode()` to an already-decoded value, manufacturing traversal sequences from double-encoded input.
   - An attacker sends `file=%252e%252e%252f` (double-encoded `../`)
   - Container decodes to: `%2e%2e%2f`
   - Line 38 decodes again to: `../`
   - This transforms an inert literal into an exploitable traversal sequence

2. **Insufficient validation**: Line 40–42 checks only for the `.." literal; it does not:
   - Canonicalize or resolve symlinks
   - Verify that the resolved path stays within `ATTACHMENTS_DIR`
   - Reject absolute paths reliably

3. **Sink misuse**: `File(parent, child)` concatenates paths textually. A child of `../etc/passwd` paired with a parent of `/var/app-data/attachments` produces `/var/app-data/attachments/../etc/passwd`, which escapes the intended directory when the file is opened.

## Fix

**Vulnerable code (lines 28–59):**

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

response.setContentType("application/octet-stream");
response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

try (InputStream in = new FileInputStream(target);
     OutputStream out = response.getOutputStream()) {
    byte[] buffer = new byte[8192];
    int read;
    while ((read = in.read(buffer)) != -1) {
        out.write(buffer, 0, read);
    }
}
```

**Fixed code:**

```java
String rawFilename = request.getParameter("file");
if (rawFilename == null || rawFilename.isEmpty()) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "file parameter is required");
    return;
}

// Do NOT apply a second URLDecoder.decode() – request.getParameter() already
// returns percent-decoded values from the servlet container.

// Reject paths with traversal sequences, absolute paths, or suspicious characters.
if (rawFilename.contains("..") || rawFilename.contains("\\") || rawFilename.startsWith("/")) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
    return;
}

File baseDir = new File(ATTACHMENTS_DIR);
File target = new File(baseDir, rawFilename);

try {
    String basePath = baseDir.getCanonicalPath();
    String targetPath = target.getCanonicalPath();
    
    // Verify the resolved target is within the base directory.
    if (!targetPath.startsWith(basePath + File.separator)) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
        return;
    }
} catch (IOException e) {
    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error processing request");
    return;
}

response.setContentType("application/octet-stream");
response.setHeader("Content-Disposition", "attachment; filename=\"" + rawFilename + "\"");

try (InputStream in = new FileInputStream(target);
     OutputStream out = response.getOutputStream()) {
    byte[] buffer = new byte[8192];
    int read;
    while ((read = in.read(buffer)) != -1) {
        out.write(buffer, 0, read);
    }
}
```

## Explanation

The fix eliminates the vulnerability by three mechanisms:

1. **Removes the second `URLDecoder.decode()`** – `request.getParameter()` already returns percent-decoded values from the servlet container. A second decode manufactures traversal sequences from inert double-encoded input (e.g., `%252e%252e%252f` becomes `../`). Removing it prevents this attack vector.

2. **Retains the traversal-sequence denylist** – the `.., \, /` checks remain as defense-in-depth, rejecting obvious traversal and absolute-path attempts without relying on canonicalization alone.

3. **Adds canonicalization and containment verification** – both the base directory and the target path are resolved to their canonical (real) form with `getCanonicalPath()`, which resolves symlinks and relative references. The containment check verifies that the resolved target stays within the base directory by comparing canonical paths with a separator-terminated base (`basePath + File.separator`). This pattern prevents sibling-directory attacks (e.g., `/app/uploads-backup` will not match `/app/uploads/`).

The sink contract is preserved: the code still constructs a File object and opens it with FileInputStream, maintaining the original functionality.

## Behaviour changes

1. **Removed double-decoding** – filenames containing literal percent-encoded sequences (`%2e`, `+`, etc.) are no longer decoded twice. Filenames with `+` will not be converted to spaces. This is the correct behavior and restores expected filename handling.

2. **Added canonicalization overhead** – two `getCanonicalPath()` calls are added, which resolve symlinks and normalize paths. This has a small performance cost but is necessary for correctness. The calls are placed before file operations, so the overhead is negligible.

3. **Added IOException handling** – a try-catch block handles canonicalization failures (e.g., permission issues or I/O errors during path resolution). On failure, the request is rejected with a 500 Internal Server Error. This is appropriate because if the base directory cannot be canonicalized, the containment check cannot be trusted.

4. **Tighter path rejection** – in addition to `..`, the code now rejects paths containing `\` and absolute paths starting with `/`. This hardens against a wider range of traversal attempts and is consistent with the guidance for defense-in-depth.

