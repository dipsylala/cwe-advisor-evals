## Verdict

Confirmed. The code is vulnerable to path traversal due to a second URL decode that manufactures `../` sequences from double-encoded input, combined with insufficient containment verification.

## Source

**Lines 30–46 (data flow):**

1. **Source** (line 30): `request.getParameter("file")` — already percent-decoded once by the servlet container
2. **Unsafe re-decode** (line 38): `URLDecoder.decode(rawFilename, "UTF-8")` — applies a second decode, converting `%252e%252e%252f` to `../`
3. **Inadequate validation** (lines 40–42): `if (filename.contains(".."))` — denylist check only, does not verify canonical containment
4. **Sink** (line 46): `new File(ATTACHMENTS_DIR, filename)` — constructs path with untrusted, unverified filename

**Attack vector:** An attacker sends `file=%252e%252e%252fpassword.txt`. The container decodes it to `%2e%2e%2fpassword.txt`. The code then decodes again to `../password.txt`. The `contains("..")` check catches this specific form, but the real issue is the absence of canonical path verification—the code does not resolve symlinks or confirm the final path is within the base directory, and it re-decodes after the container has already done so.

## Fix

**Add imports:**
```java
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
```

**Replace the entire `doGet()` method:**

```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {

    String filename = request.getParameter("file");
    if (filename == null || filename.isEmpty()) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "file parameter is required");
        return;
    }

    // Reject traversal attempts, absolute paths, and suspicious characters
    if (filename.contains("..") || filename.contains("\\") || filename.startsWith("/") || filename.contains("\0")) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
        return;
    }

    try {
        Path base = Paths.get(ATTACHMENTS_DIR).toRealPath();
        Path target = base.resolve(filename).toRealPath();

        // Verify the resolved target is within the base directory
        if (!target.startsWith(base)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

        try (InputStream in = Files.newInputStream(target);
             OutputStream out = response.getOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        }
    } catch (IOException e) {
        response.sendError(HttpServletResponse.SC_NOT_FOUND, "file not found");
    }
}
```

## Explanation

The fix addresses two defects: (1) removes the dangerous second `URLDecoder.decode()` call — the servlet container already decoded the parameter, so re-decoding manufactures traversal from double-encoded input, and (2) replaces the string `contains("..")` denylist with proper canonical path verification.

The corrected code:
- Uses the already-decoded `filename` directly without further processing
- Rejects traversal sequences (`..`, `\`, leading `/`, null bytes) upfront before path construction
- Canonicalizes both the base directory and the resolved target using `Path.toRealPath()`, which follows symlinks and eliminates relative path components (`.` and `..`)
- Verifies containment by comparing `Path` objects with `target.startsWith(base)` — not string comparison, which would accept sibling directories like `/app/uploads-backup`
- Wraps file access in a try-catch to handle `IOException` from `toRealPath()` if the file does not exist, returning a consistent 404 error

All APIs (`Path`, `Paths`, `Files.newInputStream()`) are from the Java standard library (`java.nio.file`).

## Behaviour changes

- **Removed second URL decode:** The parameter is no longer re-decoded; it is used as provided by `request.getParameter()`, which has already handled percent-decoding.
- **Upfront validation:** Filenames containing `..`, `\`, starting with `/`, or containing null bytes now fail validation with a 400 error before attempting to access the filesystem.
- **Symlink resolution:** `Path.toRealPath()` follows symbolic links and normalizes the path. Any symlink target outside the base directory is rejected with a 400 error.
- **Proper containment check:** The containment verification now uses `Path.startsWith()` on canonicalized paths, not string prefix matching, eliminating the sibling-directory bypass.
- **Consistent error handling:** All I/O errors (file not found, permission denied, symlink resolution failure) result in a 404 response, rather than potentially exposing stack traces or allowing exception propagation.
- **File stream API:** Changed from `new FileInputStream()` to `Files.newInputStream()`, which integrates with the `Path` API and handles path conversion transparently.
