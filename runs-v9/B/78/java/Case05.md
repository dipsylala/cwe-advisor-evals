## Verdict

Exploitable. Confidence: high.

CWE-78 (OS Command Injection). Untrusted HTTP request data reaches `Runtime.exec()` concatenated directly into a shell command string, with no validation or encoding anywhere along the call chain.

## Source

- **Source**: `request.getParameter("name")` - `Case05A.java`, line 16 (inside `handle(HttpServletRequest, HttpServletResponse)`).
- **Propagation**: the value is passed unmodified as `data` through `Case05B.handleSink()` (`Case05B.java` line 13) and `Case05C.handleSink()` (`Case05C.java` line 13) - each is a pure pass-through with no checks, transforms, or filtering.
- **Sink**: `Runtime.getRuntime().exec(osCommand + data)` - `Case05D.java`, line 28. `osCommand` is a fixed prefix (`cmd.exe /c dir ` on Windows, `/bin/ls ` otherwise); `data` is concatenated onto it with no escaping, quoting, or allowlisting, so request-controlled shell metacharacters (`;`, `&&`, `|`, backticks, etc.) reach the command interpreter unmodified.

## Fix

**Vulnerable code** (`Case05D.java`):

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

**Fixed code** (`Case05D.java`):

```java
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
{
    // The command was incidental - its only purpose was to list a directory's
    // contents. Replace the shell invocation with the native Java file API so
    // there is no command interpreter in the path at all.
    Path target = Paths.get(data);
    try (DirectoryStream<Path> stream = Files.newDirectoryStream(target))
    {
        for (Path entry : stream)
        {
            // Enumerate entries. The original code never read the spawned
            // process's stdout (it only called process.waitFor()), so entries
            // are enumerated here and discarded rather than written to the
            // response, preserving the original's "no output surfaced" contract.
        }
    }
    catch (IOException e)
    {
        // The original command never threw for a missing/invalid path - the
        // shell process just exited non-zero, and that exit code was discarded.
        // Swallow the equivalent failure here to preserve that behaviour.
    }
}
```

The purpose of the code is directory listing, which `dir`/`ls` provide only incidentally - `java.nio.file.Files` performs the same operation as a first-party library call, which is the primary defence in the loaded CWE-78 guidance (eliminate the command execution entirely rather than trying to sanitize it). No library recommendation applies here; the fix is a standard-library substitution, not a dependency change.

## Explanation

The vulnerability exists because `data` - fully attacker-controlled via the `name` request parameter - is concatenated directly into a string that is handed to `Runtime.getRuntime().exec()`, which (via its single-`String` overload) tokenizes and runs it through the OS shell/command interpreter. Any shell metacharacters in `data` are interpreted by `cmd.exe`/`sh` rather than treated as inert text, letting an attacker chain arbitrary commands after the intended `dir`/`ls`. Since the command here is incidental - the code's actual goal is enumerating a directory's entries - the fix removes the shell invocation entirely and replaces it with `java.nio.file.Files.newDirectoryStream()`, which performs the same enumeration directly through the OS filesystem APIs with no command interpreter involved. This closes the injection class structurally (there is no command string for metacharacters to escape into) rather than relying on escaping or allowlisting, consistent with the knowledge base's stated primary defence for CWE-78 in Java.

## Behaviour changes

- **OS branching removed**: the original selected between a Windows `cmd.exe /c dir` and a Unix `/bin/ls` based on `os.name`; `Files.newDirectoryStream()` is OS-agnostic, so the branch is gone. This is a simplification, not a functional loss - both original branches performed the same directory-listing operation.
- **Argument tokenization difference**: `Runtime.exec(String)` splits the whole command on whitespace via `StringTokenizer`, so a `data` value containing a space was previously split into multiple `dir`/`ls` arguments. `Paths.get(data)` treats the full string (including spaces) as a single path. This is closer to the evident intent (one target path) and is called out because it is an observable behavioural difference for inputs containing whitespace.
- **Failure signaling difference**: the original discarded the process's exit code (`process.waitFor()`'s return value was never read), so an invalid or inaccessible path failed silently with no exception. `Files.newDirectoryStream()` throws `IOException` (e.g. `NoSuchFileException`, `NotDirectoryException`) for the same conditions; that exception is caught and swallowed in the fix specifically to preserve the original's "failure is not surfaced" contract. If the caller actually wants failures reported, this catch block should be replaced with real handling - flagged here because that decision belongs to the developer, not the remediation.
- **No output surfaced**: preserved from the original - the process's stdout was never read or written to the response, and the fixed code likewise enumerates but does not emit directory entries anywhere. No information leak is introduced.
- **Out of scope**: `data` is still used as a filesystem path with no path-traversal or scope restriction (e.g. no check that it stays under an intended base directory). That is a distinct weakness (CWE-22/CWE-200), not CWE-78, and is left unaddressed here to keep this fix scoped to the reported command-injection finding; it should be reviewed separately.
