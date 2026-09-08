## Verdict

Confirmed. CWE-78 (OS Command Injection) - exploitable, real finding.

## Source

`Case05A.handle()` reads `request.getParameter("name")` (attacker-controlled HTTP request parameter) into local variable `data`, with no validation or encoding applied. `data` is passed unchanged through `Case05B.handleSink(data, ...)` -> `Case05C.handleSink(data, ...)` -> `Case05D.handleSink(data, ...)`, an unmodified pass-through call chain across all four files.

## Fix

### File: Case05D.java

```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Case05D
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        // SAST FINDING was: CWE-78 (OS Command Injection). The original code built an
        // OS "dir"/"ls" command by concatenating untrusted `data` and ran it via
        // Runtime.exec(). Listing a directory's contents does not require a shell
        // command at all - java.nio.file.Files provides it natively, so the command
        // execution is eliminated rather than merely parameterized.
        // An IOException here propagates via the declared `throws Throwable`, the same
        // way an IOException from the original Runtime.exec() call was left uncaught.
        Path target = Paths.get(data);
        if (Files.isDirectory(target))
        {
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(target))
            {
                for (Path entry : entries)
                {
                    // Intentionally discarded: the original command's stdout was never
                    // captured or returned either (Process output was not read before
                    // process.waitFor()), so no listing is surfaced here.
                }
            }
        }

    }
}
```

## Explanation

The sink built an OS command string (`c:\WINDOWS\SYSTEM32\cmd.exe /c dir ` or `/bin/ls `) by directly concatenating the untrusted `data` value, then ran it through a shell-invoking overload, `Runtime.getRuntime().exec(String)`. Because the whole thing is a single string handed to a shell, an attacker-supplied value such as `. & calc.exe` (Windows) or `. ; id` (Unix) breaks out of the intended `dir`/`ls` argument and executes an arbitrary second command. `Runtime.exec(String)` also tokenizes with `StringTokenizer`, which does not add any protection here since the shell is still invoked via `cmd.exe /c` / the string is still shell-interpreted on Windows.

This is a case where the command is incidental: the code's actual purpose is "list a directory's contents," which is a file-system operation Java performs natively. Per the CWE-78 guidance's primary defence (eliminate the command entirely rather than parameterize it), the fix replaces the `Runtime.exec()` call with `java.nio.file.Files.isDirectory()` / `Files.newDirectoryStream()`, resolving `data` as a `Path` and enumerating entries directly through the filesystem API. There is no shell involved at any point, so shell metacharacters in `data` have no special meaning and command injection is structurally impossible, not merely filtered.

The replacement preserves the original sink's contract: the method still returns `void`, and the directory-listing output is discarded exactly as the original discarded the external command's stdout (the original never read `Process`'s output stream before `waitFor()`). An `IOException` from `Files.newDirectoryStream()` is left to propagate via the method's existing `throws Throwable`, matching the original's behavior of leaving `Runtime.exec()`'s `IOException` uncaught. No output is newly surfaced, so the fix does not trade the injection for an information leak.

`Case05A.java`, `Case05B.java`, and `Case05C.java` are unchanged: they only pass `data` through unmodified and contain no sink.

## Behaviour changes

- The method no longer spawns an OS process (`cmd.exe`/`/bin/ls`); it instead reads the directory identified by `data` directly through `java.nio.file.Files`. Functionally equivalent for the case where `data` names an accessible directory: both the original and the fix are no-ops from the caller's perspective (no return value, no captured output, no response written).
- If `data` does not resolve to a directory (e.g. it names a file, or the path does not exist), the fix silently does nothing (`Files.isDirectory()` returns `false`), whereas the original's `dir`/`ls` command would have exited non-zero without that exit code ever being inspected either - no externally observable difference, since the original never checked or surfaced the exit status.
- An invalid path string that would throw `InvalidPathException` (unchecked) from `Paths.get(data)` propagates up via the declared `throws Throwable`, the same way a malformed command that failed to launch would have propagated an `IOException` from the original `Runtime.exec()` call.
- This fix does not address path traversal (CWE-22): `data` is still used to resolve an arbitrary filesystem path for listing. That is a separate weakness class from the OS command injection finding being remediated here and is out of scope for this finding; if the application intends `data` to be constrained to a specific base directory, that containment check should be added as a follow-up.

**Verification performed:** Compiled the fixed `Case05D.java` with `javac` (JDK 26) against stub definitions of its `javax.servlet.http` and `testcasesupport` dependencies (matching the original file's own unresolved imports) - compiled cleanly with no errors or warnings attributable to the changed code. All identifiers introduced (`java.nio.file.Files`, `Path`, `Paths`, `DirectoryStream`) are JDK standard library (`java.nio.file`), used with their documented signatures (`Files.isDirectory(Path)`, `Files.newDirectoryStream(Path)` returning an `AutoCloseable, Iterable<Path>`).
