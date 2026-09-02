## Verdict

Exploitable. Confidence: high.

## Source

`doPost` reads the incoming cookies (`request.getCookies()`), finds the one named `BenchmarkTest00002`, and URL-decodes its value into `param` (line 61: `param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");`). Cookie values are not percent-decoded by the servlet container, so this single explicit decode is the correct one, not a double-decode. `param` is fully attacker-controlled - a client can set any cookie value it likes.

Data flow to the sink: `param` (attacker-controlled) -> `fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param` (line 71, plain string concatenation, no validation) -> `new java.io.FileOutputStream(fileName, false)` (line 74, the sink). Nothing between source and sink constrains `param`, so a cookie value such as `../../../../tmp/evil` or an absolute path is concatenated onto `TESTFILES_DIR` unchanged and opened for writing, allowing files to be created or overwritten outside the intended `TESTFILES_DIR` directory.

## Fix

Vulnerable code (`doPost`, lines 67-78):

```java
String fileName = null;
java.io.FileOutputStream fos = null;

try {
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;

    // SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened.
    fos = new java.io.FileOutputStream(fileName, false);
    response.getWriter()
            .println(
                    "Now ready to write to file: "
                            + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));

} catch (Exception e) {
    System.out.println("Couldn't open FileOutputStream on file: '" + fileName + "'");
} finally {
    ...
}
```

Fixed code:

```java
String fileName = null;
java.io.FileOutputStream fos = null;

try {
    java.nio.file.Path baseDir =
            java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR)
                    .toRealPath();

    // Reject anything that is not a single, plain filename: no separators, no
    // traversal sequences, no absolute path. Canonicalizing the base (not the
    // not-yet-existing target) and then constraining the candidate to one path
    // component is required because the target file may not exist yet on this
    // write path, so toRealPath() cannot be used on the full candidate.
    java.nio.file.Path candidateName = java.nio.file.Paths.get(param).getFileName();
    if (param.isEmpty()
            || param.contains("/")
            || param.contains("\\")
            || candidateName == null
            || !candidateName.toString().equals(param)) {
        throw new java.io.IOException("Invalid file name: " + param);
    }

    java.nio.file.Path resolved = baseDir.resolve(param).normalize();
    if (!resolved.startsWith(baseDir)) {
        throw new java.io.IOException("Invalid file name: " + param);
    }

    fileName = resolved.toString();

    fos = new java.io.FileOutputStream(fileName, false);
    response.getWriter()
            .println(
                    "Now ready to write to file: "
                            + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));

} catch (Exception e) {
    System.out.println("Couldn't open FileOutputStream on file: '" + fileName + "'");
} finally {
    ...
}
```

## Explanation

The original code concatenated the attacker-controlled cookie value directly onto `TESTFILES_DIR` and passed the result straight to `FileOutputStream`, so any `../` sequence or absolute-path value in the cookie let the write escape the intended directory. The fix canonicalizes the existing base directory with `toRealPath()` (following any symlinks), then requires `param` to reduce to a single path component equal to itself via `Paths.get(param).getFileName()` - this rejects separators, `..`, and absolute paths outright rather than trying to strip them. The candidate is then resolved against the canonical base and confirmed to still start with that base using `Path.startsWith(Path)` (component-aware, not a string prefix check) before being used to open the file. Because the write target does not exist yet, `toRealPath()` is applied only to the base directory (which does exist), per the case where canonicalizing a not-yet-created target isn't possible - the single-component check on `param` closes the gap that would otherwise leave.

## Behaviour changes

- A cookie value containing `/`, `\`, `..`, or an absolute path, or an empty value, now causes an `IOException` to be thrown and caught by the existing `catch (Exception e)` block, which prints the "Couldn't open FileOutputStream" message and skips the write - previously such a value would attempt (and likely succeed at) writing outside `TESTFILES_DIR`. This is the intended effect of the fix, not an unrelated behavior change.
- `fileName` is now the canonicalized, resolved absolute path (via `toRealPath()`/`normalize()`) rather than the raw, unvalidated concatenation - this only affects the string used for logging and for the `encodeForHTML` response message; the resolved location for legitimate (non-traversal) filenames is unchanged since it still lands inside `TESTFILES_DIR`.
- All other logic - cookie lookup, `FileOutputStream` append flag (`false`), response content type, `finally`-block cleanup, exception handling - is unchanged.
