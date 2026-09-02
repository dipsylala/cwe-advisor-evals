## Verdict

Confirmed. The `doPost` handler builds a filesystem path from an attacker-controlled cookie value and opens it without validating that the resolved path stays inside the intended directory, allowing path traversal / arbitrary file read.

## Source

`request.getCookies()` → the cookie named `"BenchmarkTest00001"` → `theCookie.getValue()`, URL-decoded via `java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8")` and assigned to `param` (line 61). Cookies are attacker-controlled: a client can set any value, including sequences like `../../../../etc/passwd` or an absolute path, and URL-decoding additionally lets an attacker deliver encoded traversal sequences (e.g. `%2e%2e%2f`).

`param` flows unmodified into `fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;` (line 71), which is then passed straight into `new java.io.File(fileName)` / `new java.io.FileInputStream(...)` (line 73) — the sink. Because `param` is only concatenated, not validated or canonicalized, traversal sequences in the cookie let the resulting path escape `TESTFILES_DIR` and read arbitrary files readable by the server process.

## Fix

Replace the direct concatenation-and-open with a canonical-path containment check before the file is opened:

```java
String fileName = null;
java.io.FileInputStream fis = null;

try {
    java.io.File baseDir = new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).getCanonicalFile();
    java.io.File requested = new java.io.File(baseDir, param);
    java.io.File canonicalFile = requested.getCanonicalFile();

    if (!canonicalFile.toPath().startsWith(baseDir.toPath())) {
        throw new SecurityException("Invalid file path");
    }

    fileName = canonicalFile.getPath();
    fis = new java.io.FileInputStream(canonicalFile);
    byte[] b = new byte[1000];
    int size = fis.read(b);
    response.getWriter()
            .println(
                    "The beginning of file: '"
                            + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName)
                            + "' is:\n\n"
                            + org.owasp.esapi.ESAPI.encoder().encodeForHTML(new String(b, 0, size)));
} catch (Exception e) {
    System.out.println("Couldn't open FileInputStream on file: '" + fileName + "'");
    response.getWriter()
            .println(
                    "Problem getting FileInputStream: "
                            + org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
} finally {
    if (fis != null) {
        try {
            fis.close();
            fis = null;
        } catch (Exception e) {
            // we tried...
        }
    }
}
```

Key changes:

- Resolve the untrusted `param` against the trusted base directory with `new File(baseDir, param)`, then call `getCanonicalFile()` on both the base directory and the resolved file. Canonicalization collapses `..`, `.`, and symlink indirection so the check below cannot be bypassed by encoding tricks or relative-path games.
- Verify containment with `canonicalFile.toPath().startsWith(baseDir.toPath())` before the file is touched. Reject (throw/return an error) on failure rather than attempting to "clean" the string — stripping `../` sequences is insufficient because a stripped result can still be a different valid traversal (e.g. `....//` after single-pass removal, or an absolute path supplied directly).
- Use the canonical, validated `File` object for the actual `FileInputStream` open, not the original concatenated string, so the check and the operation act on the same resolved path (avoiding a check/use mismatch).

## Explanation

`TESTFILES_DIR + param` is a textbook path traversal sink: the base directory constant provides no protection because string concatenation does not stop `..` segments from walking back out of it, and `File`/`FileInputStream` follow whatever path they are given, including ones that resolve outside the intended root. Since `param` originates from a client-supplied, URL-decoded cookie value, an attacker fully controls its contents and can submit sequences such as `../../../../etc/passwd` (or platform equivalents) to make `fileName` resolve to a file well outside `TESTFILES_DIR`.

The fix does not rely on blocklisting `..` or other suspicious substrings, since such filters are routinely bypassed by encoding variations, redundant separators, or symlinks. Instead it establishes ground truth by resolving both the base directory and the requested file to their canonical, absolute forms and then requires the resolved file's canonical path to be a descendant of the canonical base directory. Any traversal attempt that escapes the base directory fails this containment check and is rejected before the file is ever opened, while legitimate requests for files inside `TESTFILES_DIR` continue to work unchanged. The existing HTML-encoding of the response body (via ESAPI) is unrelated to this vulnerability — it protects against reflected XSS in the output, not against the server opening the wrong file — so it is preserved but does not substitute for the containment check.
