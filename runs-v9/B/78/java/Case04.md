## Verdict

Exploitable. CWE-78, OS Command Injection. Confidence: high.

## Source

`Case04A.handle()` (Case04A.java:16) reads an unvalidated HTTP request parameter, `data = request.getParameter("name")`, and passes it unmodified into `Case04B.handleSink(data, request, response)` (Case04A.java:18). `Case04B.handleSink()` concatenates that value onto a hardcoded command prefix and passes the result to `Runtime.getRuntime().exec(...)` (Case04B.java:28) with no validation or encoding anywhere on the path.

## Fix

Vulnerable code (Case04B.java):

```java
public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
{
    String osCommand;
    if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
    {
        osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
    }
    else
    {
        osCommand = "/bin/ls ";
    }

    // SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
    Process process = Runtime.getRuntime().exec(osCommand + data);
    process.waitFor();
}
```

Fixed code (Case04B.java):

```java
public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
{
    try (java.util.stream.Stream<java.nio.file.Path> entries =
            java.nio.file.Files.list(java.nio.file.Paths.get(data)))
    {
        entries.forEach(p -> { });
    }
}
```

## Explanation

Both branches of the original code exist only to list the contents of a directory named by `data`, wrapping it in an OS shell call (`cmd.exe /c dir ...` on Windows, `/bin/ls ...` elsewhere) and concatenating the untrusted parameter directly into that command string. On the Windows branch `cmd.exe` is a shell, so metacharacters in `data` (`&`, `|`, `&&`, etc.) let an attacker run arbitrary commands; on the Unix branch `Runtime.exec(String)` still tokenizes the whole string with `StringTokenizer`, so whitespace in `data` injects extra arguments into `ls`. Per the CWE-78 Java guidance, directory listing is not a case where command execution is the point of the endpoint — it is incidental to a native filesystem operation, so the correct remediation is to eliminate the shell call entirely rather than try to sanitize it. The fix replaces both OS-specific branches with `java.nio.file.Files.list(Path)`, which enumerates directory entries directly through the JVM's filesystem APIs. `data` is used only as a path argument to a Java API, never concatenated into a string handed to a shell, so no shell metacharacter or argument-injection vector exists regardless of its contents. This is a complete elimination of the sink, not a parameterized/allowlisted invocation, so no secondary allowlist validation is needed to close CWE-78 specifically.

## Behaviour changes

- The Windows/Unix branching on `System.getProperty("os.name")` is removed: `Files.list()` is a cross-platform Java API, so the OS-specific command strings are no longer needed. This is a direct consequence of eliminating the shell call, not an independent behavior change.
- No `Process` object is created and `process.waitFor()` is removed. The original code never inspected the process's exit code or output, so nothing downstream depended on either; the replacement performs the equivalent directory-listing operation synchronously and also produces no output.
- Directory entries are enumerated and discarded (`entries.forEach(p -> { })`) rather than executed as an external command whose stdout/stderr were never read. This preserves the original's behavior of not surfacing any listing content to the caller or `HttpServletResponse` — neither the original nor the fixed method writes to `response`.
- Error behavior changes shape but not exposure: the original could throw `IOException` from `Runtime.exec()` (e.g., if `cmd.exe` or `/bin/ls` were unavailable) or silently return a non-zero exit code that was never checked; the fix throws `IOException` from `Files.list()` (e.g., `NoSuchFileException` if `data` does not resolve to an existing directory, or `NotDirectoryException` if it resolves to a file). Both are unchecked by the caller and propagate identically via the method's existing `throws Throwable`, so no new failure mode is exposed to `Case04A`.
- Out of scope for this finding: `data` is still used unvalidated to build a filesystem path, so directory traversal (CWE-22) is not addressed here — this fix closes only the reported OS command injection at Case04B.java:28. A separate review should confirm the caller constrains `data` to an expected base directory if arbitrary path traversal is a concern.
