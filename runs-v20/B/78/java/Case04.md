## Verdict

Exploitable. Confidence: high.

`Case04B.handleSink` builds an OS command by string concatenation and executes it with `Runtime.getRuntime().exec(String)`, using data that originates from an HTTP request parameter with no validation or neutralization anywhere on the path.

On the Windows branch the command is run through `cmd.exe /c`, which is itself a shell - any shell metacharacters in the parameter (`&`, `&&`, `|`, `>`, etc.) are interpreted by `cmd.exe` and let the attacker run an arbitrary second command, not just add arguments to `dir`. On the non-Windows branch the same concatenated string is tokenized by `Runtime.exec(String)`'s internal `StringTokenizer` into extra arguments/flags for `/bin/ls` (argument injection), and because the destination directory itself is fully attacker-controlled, the "listing" primitive already lets the caller enumerate arbitrary paths on the filesystem.

## Source

- Source: `request.getParameter("name")` in `Case04A.handle` (`Case04A.java:16`), an HTTP request parameter - untrusted, attacker-controlled.
- Call chain: `Case04A.handle` reads the parameter into `data` and passes it unchanged into `(new Case04B()).handleSink(data, request, response)` (`Case04A.java:18`). No validation, encoding, or allowlisting occurs anywhere in `Case04A`.
- Sink: `Runtime.getRuntime().exec(osCommand + data)` in `Case04B.handleSink` (`Case04B.java:28`), where `osCommand` is `"c:\WINDOWS\SYSTEM32\cmd.exe /c dir "` on Windows or `"/bin/ls "` otherwise, and `data` is concatenated directly onto the end with no separation, quoting, or validation.
- Sink contract before the fix:
  - **Returns**: a `Process` handle; the method calls `process.waitFor()` and discards the exit code.
  - **Discards**: the child process's stdout/stderr are never read - the listing output goes nowhere and is never written to the `HttpServletResponse`.
  - **Arguments left implicit**: no working directory, environment, or output redirection is set on the `Process` (all JVM defaults).
  - **Failure behaviour**: `Runtime.exec` can throw `IOException`, and `waitFor()` can throw `InterruptedException`; both are unhandled and propagate via the method's declared `throws Throwable`.

## Fix

### File: Case04B.java

```java
package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Case04B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        // Listing directory entries is a native Java operation - no external
        // process is required, which removes the OS command injection sink
        // entirely rather than trying to make the command construction safe.
        Path dir = Paths.get(data);
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(dir))
        {
            for (Path entry : entries)
            {
                // Original code discarded the command's output (it called
                // process.waitFor() without reading stdout); preserve that
                // behaviour here rather than surfacing directory contents.
            }
        }
    }
}
```

## Explanation

The vulnerability is the OS-command construction itself (string-concatenating a request parameter onto a `dir`/`ls` command line and handing it to `Runtime.exec`), and per the CWE-78 Java guidance the correct primary fix where the command is incidental - here, listing a directory's contents - is to remove the command execution entirely and use a native Java library for the same operation. `java.nio.file.Files.newDirectoryStream(Path)` lists the entries of a directory without spawning a process, a shell, or a `StringTokenizer`-split argument list, so there is no command string for an attacker to influence and no shell for it to be interpreted by. The `data` value still selects which directory is listed (preserving the original operation's purpose), but it can no longer be interpreted as shell syntax or as extra flags to an external program, which eliminates both the `cmd.exe` shell-injection path and the `/bin/ls` argument-injection path in one change.

## Behaviour changes

- The Windows/non-Windows `osCommand` branching and the `Runtime.exec`/`Process.waitFor()` call are removed entirely, replaced by `Files.newDirectoryStream`. This is the intended remediation, not incidental scope creep - it is the library substitution the CWE-78 Java guidance prescribes for a command whose purpose (directory listing) has a direct native-library equivalent.
- No output is written to `HttpServletResponse` or returned, matching the original method: the original never read the child process's stdout (`process.waitFor()` only waits on the exit code) and never touched `response`, so the fix preserves "discards all listing output" rather than introducing an information leak.
- Argument-style input to the original command (e.g. flags such as `-l` reaching `/bin/ls`, or extra shell commands reaching `cmd.exe`) is no longer possible - `data` is now consumed only as a single filesystem path. A caller that was relying on `data` containing multiple whitespace-separated tokens (flags, multiple paths) to influence the listing loses that ability; this is an intentional narrowing required to close the injection, not an accidental behaviour change.
- Failure behaviour is preserved in kind: `Files.newDirectoryStream` throws `IOException` (e.g. `NoSuchFileException`, `NotDirectoryException`) for a bad or non-directory path, and `Runtime.exec`/`waitFor` previously threw `IOException`/`InterruptedException` for analogous failures; both propagate unhandled through the method's declared `throws Throwable`, so error propagation to the caller is unchanged.
- This fix addresses CWE-78 (command/argument injection) only. `data` is still used unvalidated as a filesystem path, so path traversal (CWE-22, e.g. `data` containing `..` segments or an absolute path) is not addressed here and remains a separate finding if flagged.
- Verification: the fixed `Case04B.java` was copied to a scratch directory (outside the case fixture) alongside minimal stub definitions of `testcasesupport.AbstractTestCaseServlet`, `javax.servlet.http.HttpServletRequest`, and `javax.servlet.http.HttpServletResponse` (the project's actual servlet/support classpath was not read, per scope), and compiled with `javac` (JDK 26). It compiled with no errors or warnings, confirming the new `java.nio.file` imports and API calls are valid and type-correct.
- Assumption: `data` is intended to name the directory whose contents are listed (the purpose implied by concatenating it onto `dir`/`ls`), so the native-library replacement lists that same directory rather than a fixed one. Confidence is otherwise high; this assumption does not affect the injection fix itself.
