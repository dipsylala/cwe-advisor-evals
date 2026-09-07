## Verdict

EXPLOITABLE - Path traversal vulnerability allows reading/writing arbitrary files outside the intended directory.

## Source

Cookie `BenchmarkTest00002` (line 55-64), decoded at line 61 by `URLDecoder.decode()`.

## Fix

```java
@Override
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    // some code
    response.setContentType("text/html;charset=UTF-8");

    javax.servlet.http.Cookie[] theCookies = request.getCookies();

    String param = "noCookieValueSupplied";
    if (theCookies != null) {
        for (javax.servlet.http.Cookie theCookie : theCookies) {
            if (theCookie.getName().equals("BenchmarkTest00002")) {
                param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                break;
            }
        }
    }

    String fileName = null;
    java.io.FileOutputStream fos = null;

    try {
        // Canonicalize the base directory
        java.nio.file.Path baseDir = new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).getCanonicalFile().toPath();
        
        // Verify the filename does not contain path traversal sequences or separators
        if (param.contains("..") || param.contains("/") || param.contains("\\") || param.contains("\0")) {
            throw new IllegalArgumentException("Invalid filename: contains path traversal or separators");
        }
        
        // Resolve the parameter against the base directory
        java.nio.file.Path resolvedPath = baseDir.resolve(param);
        
        // Canonicalize the resolved path and verify it is contained within the base directory
        java.nio.file.Path canonicalPath = resolvedPath.toRealPath(java.nio.file.LinkOption.NOFOLLOW_LINKS);
        if (!canonicalPath.startsWith(baseDir)) {
            throw new IllegalArgumentException("Path traversal attempt detected");
        }
        
        fileName = canonicalPath.toString();

        // SAST FINDING: CWE-22 (Path Traversal) - FIXED: file path is now validated and canonicalized.
        fos = new java.io.FileOutputStream(fileName, false);
        response.getWriter()
                .println(
                        "Now ready to write to file: "
                                + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));

    } catch (Exception e) {
        System.out.println("Couldn't open FileOutputStream on file: '" + fileName + "'");
        //			System.out.println("File exception caught and swallowed: " + e.getMessage());
    } finally {
        if (fos != null) {
            try {
                fos.close();
                fos = null;
            } catch (Exception e) {
                // we tried...
            }
        }
    }
}
```

## Explanation

The vulnerability arises from using untrusted user input (cookie value) to construct a file path without validation. An attacker can inject `../` sequences to traverse outside the intended directory.

The fix applies three controls:

1. **Reject traversal sequences upfront**: Check the parameter for `..`, `/`, `\`, and null bytes, rejecting any attempt to include path separators or directory traversal markers. This is a defensive first gate.

2. **Canonicalize the base directory**: Convert `Utils.TESTFILES_DIR` to a canonical absolute path using `File.getCanonicalFile()`, which resolves symlinks and normalizes the path.

3. **Resolve and re-verify containment**: Use `Path.resolve(param)` to combine the base with the filename, then call `toRealPath(LinkOption.NOFOLLOW_LINKS)` to canonicalize the result. The `NOFOLLOW_LINKS` option prevents symlink-following attacks at the target location. Finally, verify the resolved path starts with the base directory using `Path.startsWith(Path)` — this is component-aware comparison that prevents false positives like `/app/uploads-backup` passing a string prefix check.

The fix uses `java.nio.file.Path` APIs exclusively for path comparison, avoiding string-based prefix checks that are vulnerable to sibling-directory bypasses.

## Behaviour changes

**Rejections**: Requests with filenames containing `../`, `/`, `\\`, or null bytes are now rejected with an `IllegalArgumentException`.

**Path resolution**: File operations now resolve to the canonical absolute path, eliminating symlink ambiguity.

**Error handling**: The exception thrown on invalid filenames is caught by the existing try-catch block (line 80), which logs and continues, maintaining backward compatibility with the application's error handling flow.

**No impact on valid filenames**: Legitimate filenames (alphanumeric, dots, hyphens, underscores) that do not traverse escape the base directory pass validation unchanged.
