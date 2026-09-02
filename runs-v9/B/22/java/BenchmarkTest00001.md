## Verdict

Exploitable. CWE-22 (Path Traversal), confidence: high.

## Source

`doPost` reads a cookie named `BenchmarkTest00001` from `request.getCookies()`, URL-decodes its value with `java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8")`, and stores it in `param`. `param` is fully attacker-controlled: an attacker sets their own cookie header.

## Fix

Vulnerable code (line 71-73):

```java
fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
// SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened. Sink is the next statement.
fis = new java.io.FileInputStream(new java.io.File(fileName));
```

`param` is concatenated directly onto the base directory with no canonicalization or containment check, so a value such as `../../../../etc/passwd` (or its Windows equivalent) escapes `TESTFILES_DIR` and the resulting `FileInputStream` reads it.

Fixed code:

```java
fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;

java.nio.file.Path baseDir =
        java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toRealPath();
java.nio.file.Path candidate = baseDir.resolve(param).normalize();
if (!candidate.startsWith(baseDir)) {
    throw new java.io.IOException("Invalid file path: " + param);
}
java.nio.file.Path resolvedPath = candidate.toRealPath();
if (!resolvedPath.startsWith(baseDir)) {
    throw new java.io.IOException("Invalid file path: " + param);
}

fis = new java.io.FileInputStream(resolvedPath.toFile());
```

(`fileName` itself is left unchanged - it is still used only for the log line and the "beginning of file" message - the fix changes what is actually opened.)

## Explanation

The base directory `TESTFILES_DIR` is canonicalized once with `toRealPath()`, which follows symlinks and resolves it to an absolute real path. The attacker-controlled `param` is resolved against that base with `Path.resolve()` and `normalize()` and checked with `Path.startsWith(Path)` against the canonicalized base (not a raw string comparison, which a sibling directory such as `TESTFILES-secret` could pass). Because `normalize()` alone does not follow symbolic links, the candidate is then canonicalized with a second `toRealPath()` and checked with `startsWith` again, so a symlink planted inside the base that points outside it is also caught. `FileInputStream` is opened only from this validated, resolved `Path`, never from the raw concatenated string, satisfying the guidance's requirement to validate the same value that is actually used at the sink. An absolute or traversal-laden `param` fails one of the two `startsWith` checks (Java's `Path.resolve()` returns an absolute `other` argument unchanged, so an absolute path such as `/etc/passwd` is rejected by the first check rather than silently accepted) and the request falls into the existing `catch (Exception e)` block, which already handles "file not found" style errors.

## Behaviour changes

- A request whose cookie value resolves outside `TESTFILES_DIR` now throws `IOException("Invalid file path: ...")` instead of opening and returning the out-of-bounds file. This is caught by the pre-existing `catch (Exception e)` block, so the response for such a request changes from leaking file contents to the existing "Problem getting FileInputStream: <message>" error page - this is the intended effect of the fix, not a side effect.
- The file is now required to exist for `toRealPath()` to succeed (both on the base directory and the resolved candidate); this matches the existing sink, since `FileInputStream` already required the target to exist to open successfully, so no new failure mode is introduced for legitimate requests.
- `fileName`, the string shown in the console log and echoed back to the client in the success/error messages, is unchanged and still holds the naive concatenation of `TESTFILES_DIR` and `param` - only the path object actually passed to `FileInputStream` changed. For legitimate (non-traversal) input the two designate the same file, so displayed output is unaffected.
- No change to `doGet`, response headers, cookie handling, or the `finally` block's stream-close logic.
