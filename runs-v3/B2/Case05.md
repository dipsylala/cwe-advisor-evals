# Case05 - CWE-78 (OS Command Injection)

- **Location:** `evals/cases-v2/Case05/Case05D.java:28`
- **Confidence:** high

## Verdict

exploitable

## Source

Untrusted data enters at `Case05A.handle()` line 16 as `request.getParameter("name")` - an attacker-controlled HTTP request parameter.

Path to the sink, with no validation, sanitisation, encoding or type conversion at any hop:

1. `Case05A.handle()` line 16: `data = request.getParameter("name")`
2. `Case05A.handle()` line 18: passes `data` to `new Case05B().handleSink(data, request, response)`
3. `Case05B.handleSink()` line 13: passes `data` unchanged to `new Case05C().handleSink(...)`
4. `Case05C.handleSink()` line 13: passes `data` unchanged to `new Case05D().handleSink(...)`
5. `Case05D.handleSink()` line 28 (sink): `Runtime.getRuntime().exec(osCommand + data)`

`osCommand` is chosen from `System.getProperty("os.name")`: on Windows it is `c:\WINDOWS\SYSTEM32\cmd.exe /c dir `, on other platforms `/bin/ls `. The parameter is concatenated onto that string.

On Windows the concatenation lands inside a `cmd.exe /c` command line, so shell metacharacters in the parameter are interpreted by the shell: `?name=.%20%26%20whoami` runs `whoami`, and `&`, `|`, `&&` and the backtick all give arbitrary command execution with the servlet container's privileges. On Linux there is no shell, but `Runtime.exec(String)` tokenises the concatenated string with `StringTokenizer`, so the parameter still becomes one or more attacker-chosen arguments to `/bin/ls`, including ones beginning with `-` that are read as options (CWE-88). Both branches are reachable from an unauthenticated request.

Sink contract as it stands today: `exec` returns a `Process` used only for `waitFor()`; the process's stdout and stderr are never read, so no command output reaches the response; the environment and working directory are inherited (the single-argument overload passes no `envp` and no `dir`); a failed *launch* throws `IOException`, but a non-zero exit status from `dir`/`ls` (missing or unreadable directory) is discarded and the method returns normally. Any replacement has to keep all four of those properties.

## Fix

Listing a directory is incidental to what this code needs to do - the JDK does it natively - so the process execution is removed rather than made safe, which deletes the sink entirely instead of hardening it.

Vulnerable code (`Case05D.java`):

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


    // Untrusted request parameter concatenated into an OS command line and
    // handed to cmd.exe /c on Windows - arbitrary command execution.
    Process process = Runtime.getRuntime().exec(osCommand + data);
    process.waitFor();

}
```

Fixed code (complete file):

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

public class Case05D
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        try
        {
            Path directory = Paths.get(data);

            try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory))
            {
                for (Path entry : entries)
                {
                    // Enumerated in-process, as the shelled-out listing was.
                    // The original never read the command's output, so no
                    // entry is surfaced to the caller or the response.
                }
            }
        }
        catch (InvalidPathException | IOException listingFailed)
        {
            // The original discarded the command's exit status, so a missing,
            // unreadable or malformed path returned normally. Preserved here.
        }

    }
}
```

No new dependency is required; `java.nio.file` has been in the JDK since Java 7.

## Explanation

The parameter was concatenated into a command line that, on Windows, was handed to `cmd.exe /c`, so anything the caller put in `name` was parsed by a shell and executed; on Linux the same concatenation fed attacker-chosen tokens to `/bin/ls` as arguments. Because enumerating a directory is something the JDK does natively, the fix removes the command execution altogether rather than trying to quote or filter the input: `Files.newDirectoryStream` takes a `Path` object, not a command string, so there is no command line for the parameter to break out of and no interpreter to attack - the value can only ever name a directory, and shell metacharacters, argument separators and a leading `-` lose all meaning. This also retires the `os.name` branch, whose only purpose was to pick a per-platform shell invocation, and with it the `cmd.exe` re-parsing problem that switching to an argument array would not have solved on Windows anyway. Entries are enumerated and discarded exactly as the process output was, so closing the injection does not open an information leak.

## Behaviour changes

- **Process execution removed.** No child process is created; the listing runs in-process through `java.nio.file`. This is the change that closes the weakness - it deletes the sink rather than sanitising its input. Consequences: no dependency on `cmd.exe` or `/bin/ls` being present, no process exit code, and no `IOException` from a failed *launch* of the interpreter.
- **`os.name` branch removed.** It existed only to select a platform-specific shell/command string; `Files.newDirectoryStream` is platform-neutral, so the branch has no remaining purpose. The reason ties directly to the weakness: the Windows branch was the `cmd.exe /c` shell that made the finding exploitable.
- **`process.waitFor()` removed.** Enumeration is synchronous, so there is nothing to wait on. The original discarded `waitFor()`'s return value, so no signal is lost.
- **Failure behaviour preserved deliberately.** `dir`/`ls` exiting non-zero for a missing or unreadable directory was silently ignored by the original; the `catch` of `IOException` and `InvalidPathException` keeps the method returning normally in those cases. Without it, a bad `name` would newly throw out of the servlet - both a behaviour change and a directory-existence oracle the original did not offer.
- **Output still discarded.** No directory entry is written to the response or returned, matching the original, which never read the process's stdout or stderr. The fix therefore closes the injection without introducing an information leak.
- **Signature, parameters and `throws Throwable` unchanged.** `request` and `response` remain unused, as before. Callers `Case05A`, `Case05B` and `Case05C` need no edit.
- **Imports added:** `java.io.IOException` and five `java.nio.file` types, required by the replacement. No third-party dependency, no manifest change.
- **Not changed (flagged, not fixed):** `data` still names the directory that gets enumerated, so the caller still chooses the path - exactly as `ls <name>` did. Since no entry is surfaced, nothing is disclosed, and confining the path to a fixed base directory would be a functional restriction beyond this finding. If the endpoint is meant to serve only one directory tree, resolve against a fixed base and verify containment after `toRealPath()` as separate hardening.

## Assumptions

- The call chain in the finding was confirmed by reading all four files; `data` is passed through `Case05B` and `Case05C` untouched, so the reported path holds.
- The intent of the sink is taken to be "enumerate the directory named by the parameter", read from `dir`/`ls` plus the discarded output. The replacement preserves that intent, including its discarding of results.
