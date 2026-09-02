## Verdict

exploitable (high confidence)

- **cwe_id**: CWE-78 (OS Command Injection)
- **location**: `Case06E.java`, line 28 (`Runtime.getRuntime().exec(osCommand + data)`)

## Source

`request.getParameter("name")` in `Case06A.handle` (`Case06A.java` line 16). This is a raw HTTP request parameter — fully attacker-controlled, no validation or encoding applied at the point it is read.

Call chain (unmodified pass-through of the tainted value at every hop):

```
Case06A.handle(request, response)
  data = request.getParameter("name")            // source
  -> Case06B.handleSink(data, ...)
     -> Case06C.handleSink(data, ...)
        -> Case06D.handleSink(data, ...)
           -> Case06E.handleSink(data, ...)
              osCommand = "cmd.exe /c dir " | "/bin/ls "
              Runtime.getRuntime().exec(osCommand + data)   // sink, line 28
```

`data` reaches the sink unchanged — no sanitization, allowlisting, or length/character restriction anywhere in the chain.

## Fix

Sink contract established before fixing (per KB Step 4):
- **Returns**: the method is `void`; the `Process` object is used only to call `waitFor()`, then discarded.
- **Discards**: the command's stdout/stderr are never read — output is not captured, logged, or written to `response`.
- **Arguments left implicit**: no explicit working directory, environment, or charset override.
- **Failure behaviour**: `exec()` can throw `IOException`; `waitFor()` can throw `InterruptedException`; both propagate via the method's `throws Throwable`. The child's exit code is never checked.

The command here is incidental — `dir`/`ls` is just enumerating a directory — so per the KB's primary remediation this eliminates the shell call entirely in favor of the JDK's own file APIs, rather than moving to a "safer" `ProcessBuilder` invocation of the same shell.

**Vulnerable code** (`Case06E.java`):

```java
public class Case06E
{
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
}
```

**Fixed code** (`Case06E.java`):

```java
package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Case06E
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        // List the requested directory using the JDK's own file APIs instead of
        // shelling out to "cmd.exe /c dir" / "/bin/ls". No external process is
        // spawned and no command string is built, so there is no shell for
        // untrusted input to inject into. This also removes the OS-specific
        // branching entirely, since Files is cross-platform.
        Path target = Paths.get(data == null ? "." : data);

        try (DirectoryStream<Path> entries = Files.newDirectoryStream(target))
        {
            for (Path entry : entries)
            {
                // Original code (Runtime.exec + waitFor with no output capture)
                // discarded the listing entirely; preserved here rather than
                // introducing a new information leak by writing entries to
                // the response.
            }
        }
    }
}
```

## Explanation

The original code built an OS command line by string-concatenating an unvalidated HTTP parameter directly after `cmd.exe /c dir ` (Windows) or `/bin/ls ` (Unix), then executed it with `Runtime.exec(String)`. On the Windows branch this re-enters `cmd.exe`, which parses the full command line itself, so `data` containing shell metacharacters (e.g. `& calc.exe`, `| whoami`) is interpreted by the shell rather than treated as a single directory argument — classic OS command injection. The fix removes the process/shell invocation entirely and replaces it with `java.nio.file.Files.newDirectoryStream()`, which enumerates a directory's entries directly through the JVM's file-system APIs. Because no external process or command string is ever constructed, there is no interpreter left for injected metacharacters to reach — the weakness is eliminated by removing the sink rather than by trying to sanitize input feeding it. The `try`-with-resources block iterates and discards each entry, matching the original's behavior of not surfacing any output.

## Behaviour changes

- **Cross-platform branch removed**: the `os.name` check selecting `cmd.exe` vs `/bin/ls` is gone — `Files.newDirectoryStream` behaves the same on every platform the JVM runs on, so the OS-specific command strings are no longer needed. Reason: required to eliminate the shell call; the two branches existed only to select a shell command, not for any behavior a caller depends on.
- **Failure type changes**: the original could throw `IOException` (failed process launch) or `InterruptedException` (`waitFor`); the fixed code instead throws `IOException` subtypes from `Files.newDirectoryStream` (e.g. `NoSuchFileException`, `NotDirectoryException`) or, if `data` resolves to an invalid path string, `InvalidPathException` (a `RuntimeException`). All are `Throwable` and propagate the same way through the method's existing `throws Throwable`, but callers matching on a specific exception type would see a different one. Reason: unavoidable consequence of swapping the process API for the file API; no behavior in the surrounding call chain (`Case06A`-`D`) inspects the specific exception type, so this is not expected to change observable behavior for this chain.
- **`null` parameter handling differs slightly**: the original would append the literal string `"null"` to the command (`data` being `null` from a missing `name` parameter), typically causing the listing command to fail silently (exit code ignored, output discarded) with no exception. The fixed code maps `null` to `"."` (list the current working directory) rather than reproducing the literal-`"null"`-path behavior, since the original's outcome was arbitrary depended on OS command semantics rather than being a real, intentional value. Reason: preserves "no exception on missing parameter" as the closest equivalent to the original's silent-failure path.
- **No return-value or output-visibility change**: the listing's contents are still discarded and never written to `response` or returned, matching the original's discard behavior exactly, so no new information disclosure is introduced.
- **Residual note (out of scope for this fix)**: `data` is still used, unvalidated, as a filesystem path (now via `Paths.get`), so a value such as `../../etc` could list a directory outside any application-intended root — a path-traversal concern (CWE-22), distinct from the OS command injection this fix addresses. If the endpoint's intended scope is a specific base directory, constrain `target` to stay within it as a separate follow-up.

**Assumptions**: `data` was treated as a directory path argument to `dir`/`ls`, consistent with how it is concatenated after the command name in the original code, in order to select the JDK file-API replacement per the KB's primary remediation strategy (eliminate the command, use a native library alternative) rather than the last-resort `ProcessBuilder` parameterized-execution fallback.
