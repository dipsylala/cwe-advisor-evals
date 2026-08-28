## Verdict

exploitable

## Source

Untrusted data enters at `e:/Github/cwe-advisor/evals/cases-v2/Case06/Case06A.java` line 16, `data = request.getParameter("name")` - an attacker-controlled HTTP query/form parameter.

Path to the sink:

- `Case06A.java:16` - `data` assigned from `request.getParameter("name")`.
- `Case06A.java:18` - passed to `(new Case06B()).handleSink(data, request, response)`.
- `Case06B.java:13` - forwarded verbatim to `(new Case06C()).handleSink(data, request, response)`.
- `Case06C.java:13` - forwarded verbatim to `(new Case06D()).handleSink(data, request, response)`.
- `Case06D.java:13` - forwarded verbatim to `(new Case06E()).handleSink(data, request, response)`.
- `Case06E.java:28` (sink) - concatenated into the command string and executed: `Runtime.getRuntime().exec(osCommand + data)`.

All three intermediate hops are pure pass-throughs: none validates, rewrites, or reassigns the value, so the taint reaches the sink intact.

## Fix

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
    private static final Path BASE_DIR = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();

    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        if (data == null)
        {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        Path target;
        try
        {
            target = BASE_DIR.resolve(data).normalize();
        }
        catch (InvalidPathException e)
        {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        if (!target.startsWith(BASE_DIR) || !Files.isDirectory(target))
        {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        try (DirectoryStream<Path> entries = Files.newDirectoryStream(target))
        {
            for (Path entry : entries)
            {
                // consume the listing as the original command output was consumed
                response.getWriter().println(entry.getFileName().toString());
            }
        }
        catch (IOException e)
        {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
    }
}
```

## Explanation

The command being assembled was a directory listing (`cmd.exe /c dir` on Windows, `/bin/ls` otherwise) with the request parameter appended, so the attacker's value became part of a command line - on Windows the `cmd.exe /c` prefix lets `&`, `|`, or `&&` chain arbitrary commands, and even without a shell `Runtime.exec(String)` tokenises the concatenated string so the value is re-split into further arguments. The four-hop call chain adds distance between the source and the sink but no defence: because every hop passes the same reference through unchanged, the fix belongs at `Case06E`, where the value is actually assembled into a command and where any other caller would otherwise reach the same sink. Process execution is removed entirely in favour of `java.nio.file.Files.newDirectoryStream`, the native Java equivalent of the operation the command performed, leaving no command string and no shell for an injection to target. Because the parameter is still used as a path, the replacement resolves it against a fixed base directory, normalises it, and rejects anything escaping that base, so closing the command injection does not introduce a path traversal.
