## Verdict

exploitable

## Source

Untrusted data enters at `Case06A.handle`, line 16: `data = request.getParameter("name")` - an attacker-controlled HTTP request parameter on a servlet endpoint.

Path from source to sink:

1. `Case06A.java:16` - `request.getParameter("name")` assigned to `data`.
2. `Case06A.java:18` - `data` passed unmodified to `(new Case06B()).handleSink(data, request, response)`.
3. `Case06B.java:13` - forwards `data` unmodified to `Case06C.handleSink`.
4. `Case06C.java:13` - forwards `data` unmodified to `Case06D.handleSink`.
5. `Case06D.java:13` - forwards `data` unmodified to `Case06E.handleSink`.
6. `Case06E.java:28` - sink: `Runtime.getRuntime().exec(osCommand + data)`, where `osCommand` is `"c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir "` on Windows or `"/bin/ls "` elsewhere.

No layer in the chain validates, encodes, or reassigns `data`; it reaches the sink byte-for-byte as received.

The path is exploitable. On Windows the command string invokes `cmd.exe /c`, which re-parses the whole command line, so shell metacharacters in `data` (`&`, `|`, `&&`, `^`, quotes) run arbitrary commands - a request such as `?name=.%20%26%20whoami` executes `whoami`. On non-Windows platforms `Runtime.exec(String)` tokenizes the string with `StringTokenizer` rather than handing it to a shell, so metacharacters are not interpreted, but the resulting tokens still become additional `ls` arguments, giving attacker-controlled option and path injection into the invoked program.

Sink contract as it stands today: `exec` returns a `Process` whose only use is `waitFor()`; the process's stdout and stderr are never read and never written to the response, and the exit status returned by `waitFor()` is discarded. The single-argument `exec` overload leaves the environment and working directory implicit, so the child inherits both from the JVM. `exec` throws `IOException` only when the program itself cannot be started; a bad or missing directory in `data` is a non-fatal, silently ignored non-zero exit. `handleSink` declares `throws Throwable`, so anything thrown does propagate to the caller.

## Fix

Listing a directory is incidental to running a program - `java.nio.file` does it natively - so the fix removes process execution entirely rather than trying to escape the input. No dependency is added; `java.nio.file` is part of the JDK.

Vulnerable code (`Case06E.java`):

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


    // VULNERABLE: attacker-controlled `data` is concatenated into a command
    // string. On Windows `cmd.exe /c` re-parses that line, so shell
    // metacharacters in `data` execute arbitrary commands.
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

public class Case06E
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        if(data == null)
        {
            // The original concatenated a missing parameter as the literal
            // text "null", which listed nothing and was ignored.
            return;
        }

        Path target;
        try
        {
            target = Paths.get(data);
        }
        catch(InvalidPathException exception)
        {
            // A name the platform cannot represent as a path previously just
            // produced a failed listing that the caller ignored.
            return;
        }

        try(DirectoryStream<Path> entries = Files.newDirectoryStream(target))
        {
            for(Path entry : entries)
            {
                // Entries are intentionally discarded: the original never read
                // the process output, and returning it here would replace the
                // injection with a disclosure of directory contents.
            }
        }
        catch(IOException exception)
        {
            // The original discarded the command's exit status, so a missing or
            // unreadable directory stays non-fatal here as well.
        }

    }
}
```

## Explanation

The directory listing no longer goes through an operating system command: `Runtime.getRuntime().exec()` and the platform-dependent `cmd.exe /c dir` and `/bin/ls` command strings are gone, replaced by `Files.newDirectoryStream`, which takes the requested location as a `Path` object rather than as text spliced into a command line. That removes the sink instead of merely escaping what flows into it - there is no shell left to re-parse the input and no argument vector for the input to be tokenized into, so metacharacters such as `&`, `|`, and `^`, and leading-hyphen values that a program would otherwise read as options, are all treated as ordinary characters in a file name. Using one portable API also erases the Windows-versus-Unix split that made the original dangerous in a different way on each platform. The iteration deliberately produces nothing, because the original read neither the child process's output nor its exit status; preserving that discard keeps the change from turning a closed injection into a new disclosure of directory contents, and the surrounding null check and caught `IOException` keep the method's silent-on-failure behaviour identical to what callers see today.

## Behaviour changes

- **Process execution removed.** The original spawned `cmd.exe` or `/bin/ls` as a child process; the fixed code performs the enumeration in-process. Reason: this is the removal of the sink and is what closes the weakness. Anything that observed the child externally - process accounting, an audit trail of spawned commands, a monitor watching for `cmd.exe` children of the JVM - will no longer see it. Nothing in the supplied call chain depends on the child process existing.
- **`InvalidPathException` and `IOException` from the listing are caught and discarded.** Reason: preserves the original failure contract rather than changing it. `exec` threw only when the executable itself could not be started; a nonexistent, unreadable, or malformed directory name produced a non-zero exit status that `waitFor()` returned and the code ignored. `Files.newDirectoryStream` reports those same data-driven conditions as exceptions, so without the catch a request naming a missing directory would newly propagate through `throws Throwable` to the container and surface as a 500 rather than the silent success it produces today.
- **Null input returns early.** Reason: `request.getParameter("name")` returns `null` when the parameter is absent, and the original concatenation turned that into the literal string `"null"`, which failed to list and was ignored. `Paths.get(null)` would instead throw `NullPointerException`, so the guard keeps the missing-parameter case a silent no-op exactly as before.
- **Multi-token input no longer lists multiple targets.** Reason: an unavoidable consequence of removing the tokenizing `exec(String)` overload. Previously `Runtime.exec(String)` split `data` on whitespace, so `a b` listed two paths on Unix; the fixed code treats the whole value as a single path name. That splitting is the argument-injection vector itself, so it is not preserved by design. A caller legitimately relying on space-separated names would need to pass them as separate requests.
- **Environment and working directory unchanged.** The single-argument `exec` overload left both implicit so the child inherited them from the JVM; resolving a relative `data` through `Paths.get` likewise resolves against the JVM's working directory, and no environment is involved. No security-relevant default was silently replaced with a different value.
- **Return value, response body, and method signature unchanged.** The method still returns `void`, writes nothing to `response`, and keeps `throws Throwable`.

Residual difference worth a reviewer's attention: the fix can no longer distinguish "the listing program could not be started" from "the directory could not be read", because the enumeration is not a separate program any more. A missing `/bin/ls` previously threw `IOException` out of `handleSink`; that condition no longer exists, and all listing failures are now swallowed. Since the original already discarded every data-driven failure and the callers ignore the outcome entirely, this was judged the closer match to existing behaviour than propagating exceptions no caller handles. If the surrounding application does want listing failures to be visible, add that deliberately as a separate change rather than as a side effect of this one.

Assumptions resolved without confirmation, since no human was available:

1. The endpoint's purpose is to list a directory named by the request parameter, not to run user-supplied commands, so eliminating process execution is a fix rather than a feature regression. Supported by the hard-coded `dir`/`ls` prefix, which permits no other operation.
2. `data` names a single path, per the whitespace-tokenization point above.
3. No path-containment or allowlist restriction was added on which directory may be listed, because the original imposed none and the reported weakness is command injection. If this endpoint is reachable by untrusted users, the ability to name an arbitrary directory should be assessed separately as a path-traversal concern.

Confidence: high. The trace is a direct five-file chain with no branching, reassignment, or sanitisation, and the fix rests on a JDK API rather than a third-party library, so there is no version or advisory claim to verify.
