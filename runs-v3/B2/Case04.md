## Verdict

exploitable

## Source

Untrusted data enters at `Case04A.handle()` (`Case04A.java:16`) as `request.getParameter("name")`, an attacker-controlled HTTP request parameter. It is assigned to `data` and passed unchanged as the first argument to `new Case04B().handleSink(data, request, response)` (`Case04A.java:18`).

Inside `Case04B.handleSink()` (`Case04B.java:11`) `data` is never validated, encoded, or constrained. It is concatenated directly onto a fixed command prefix - `"c:\WINDOWS\SYSTEM32\cmd.exe /c dir "` on Windows or `"/bin/ls "` elsewhere - and the resulting single string reaches the sink `Runtime.getRuntime().exec(osCommand + data)` at `Case04B.java:28`, followed by `process.waitFor()` at line 29.

The path is complete and unguarded: source (`request.getParameter`) to sink (`Runtime.exec`) in two hops with no trust boundary in between. On the Windows branch the command is executed by `cmd.exe /c`, which re-parses its command line, so a parameter such as `x&whoami` yields arbitrary command execution. On the Unix branch `Runtime.exec(String)` tokenises with `StringTokenizer`, so the value becomes additional `/bin/ls` arguments - argument injection at minimum (arbitrary directory enumeration, option smuggling).

Sink contract as it stands today: `exec` returns a `Process` whose only use is `waitFor()`; the exit status returned by `waitFor()` is discarded, and the child's stdout and stderr are never read and never written to `response`, so the listing's output is thrown away. No environment map and no working directory are supplied, so the child inherits both from the JVM. Failure to *start* the program throws `IOException`, which propagates out through the method's `throws Throwable`; a command that starts and then *fails* (missing path, permission denied) is silent, because the exit code is dropped. Only the blocking wait and any filesystem side effects are observable.

## Fix

The command is incidental here: the endpoint enumerates a directory named by the request parameter, and the result is discarded. `java.nio.file` performs that natively, which removes the process launch - and `cmd.exe` with it - rather than trying to quote around it. Passing an argument array would not be enough on the Windows branch, because `dir` is a `cmd.exe` builtin: any array form still has to re-enter `cmd.exe`, which parses the joined command line itself and leaves the injection point open.

Complete fixed `Case04B.java`:

```java
package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Case04B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        if (data == null)
        {
            return;
        }

        Path target;
        try
        {
            target = Paths.get(data);
        }
        catch (InvalidPathException exception)
        {
            // The original command tolerated an unusable argument without reporting it.
            return;
        }

        if (!Files.isDirectory(target))
        {
            // A listing of a missing or non-directory path produced no observable result before.
            return;
        }

        try (DirectoryStream<Path> entries = Files.newDirectoryStream(target))
        {
            for (Path entry : entries)
            {
                // The listing is performed and discarded, exactly as the command's output was.
            }
        }
        catch (IOException exception)
        {
            // A failed listing was silent before; keep it silent.
        }

    }
}
```

`Case04A.java` needs no change: it is a plain parameter hand-off, and the fix belongs at the point where the value would have become a command.

## Explanation

The weakness was the construction of an OS command by string concatenation, so the fix removes command construction altogether instead of trying to neutralise the concatenated value. The `os.name` branch, the `cmd.exe /c dir` and `/bin/ls` prefixes, and the `Runtime.exec` call are replaced by a `java.nio.file` directory enumeration: the request value is now interpreted only as a filesystem path by `Paths.get`, and is passed to `Files.newDirectoryStream` as a single typed `Path` argument that is never parsed as a command line. With no shell and no external program in the flow, shell metacharacters (`&`, `|`, `;`, backticks) and option-like values are inert data - there is nothing left to interpret them, which closes both the command injection and the argument-injection variant that an argument-array rewrite would have left behind. The rest of the original contract is preserved deliberately: the enumeration result is discarded exactly as the command's output was, nothing is written to `response`, relative paths still resolve against the JVM working directory, the call still blocks until the listing completes, and a listing that cannot be performed still passes silently rather than surfacing an error the original never surfaced.

## Behaviour changes

- **Platform branch removed.** The `System.getProperty("os.name")` test and both command strings are gone. Reason: they existed only to pick a shell or binary for the sink being removed; the `java.nio.file` listing is platform-independent, so the branch has no remaining purpose.
- **No child process is spawned; `Process` and `waitFor()` removed.** Reason: eliminating process execution is the fix. The call still blocks until the directory enumeration finishes, so the caller's synchronous timing is preserved, but process-level side effects (a `cmd.exe` or `ls` entry in process accounting, inherited environment and stdio handles) no longer occur.
- **Output remains discarded.** The enumerated entries are intentionally not collected, returned, logged, or written to `response`. Reason: the original read neither stdout nor stderr; surfacing the listing now would trade the injection for an information leak.
- **Discarded exit status becomes discarded exceptions.** The original dropped `waitFor()`'s exit code, so a failing command was silent. The fix keeps that silence by returning early for `null`, syntactically invalid, and non-directory inputs, and by catching `IOException` from the listing. Reason: propagating those conditions would make the method throw where it previously did not, and would hand an attacker an existence and permission oracle the original did not offer.
- **Start-failure exception no longer occurs.** The original could throw `IOException` from `exec` when the shell or `/bin/ls` could not be launched. Reason: there is no program to launch. The `throws Throwable` signature is unchanged, so `Case04A` needs no edit.
- **Path scope is unchanged, not narrowed.** Any directory readable by the JVM user can still be enumerated, as before. Reason: the original imposed no base directory, and inventing one would be a functional change beyond this finding. This is a strict reduction in exposure, since arbitrary command execution is gone, but if the deployment has a known content root, confining `target` to it - resolve against the root, `normalize()`, then verify `startsWith()` the root - is worthwhile hardening against directory probing and should be raised separately.
- **Assumption.** No confirmation of intent was available, so the endpoint's purpose was taken to be "list the directory named by the `name` parameter", inferred from the fixed `dir` and `ls` prefixes and the discarded output, rather than "run a caller-supplied command". If arbitrary command execution is genuinely the feature, this fix is a regression, and the correct remediation is a server-side allowlist mapping the parameter to a fixed, pre-approved command invoked through `ProcessBuilder` with a separate argument list and no shell. Confidence in the trace: high. Confidence in the fix: high, given that assumption.
