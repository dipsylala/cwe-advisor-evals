## Verdict

exploitable

## Source

Untrusted data enters at `e:/Github/cwe-advisor/evals/cases-v2/Case05/Case05A.java` line 16, `data = request.getParameter("name")` - an attacker-controlled HTTP query/form parameter.

Path to the sink:

- `Case05A.java:16` - `data` assigned from `request.getParameter("name")`.
- `Case05A.java:18` - passed to `(new Case05B()).handleSink(data, request, response)`.
- `Case05B.java:13` - forwarded verbatim to `(new Case05C()).handleSink(data, request, response)`.
- `Case05C.java:13` - forwarded verbatim to `(new Case05D()).handleSink(data, request, response)`.
- `Case05D.java:28` (sink) - concatenated into the command string and executed: `Runtime.getRuntime().exec(osCommand + data)`.

The two intermediate hops are pure pass-throughs: neither validates, rewrites, nor reassigns the value, so the taint reaches the sink intact.

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

public class Case05D
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

The command being assembled was a directory listing (`cmd.exe /c dir` on Windows, `/bin/ls` otherwise) with the request parameter appended, so the attacker's value became part of a command line - on Windows the `cmd.exe /c` prefix lets `&`, `|`, or `&&` chain arbitrary commands, and even without a shell `Runtime.exec(String)` tokenises the concatenated string so the value is re-split into further arguments. The fix is applied at the sink rather than at any of the three call sites above it, because that is the point where the value is actually assembled into a command; a check added in `Case05A`, `Case05B`, or `Case05C` would still leave `Case05D` reachable from any other caller. Process execution is removed entirely in favour of `java.nio.file.Files.newDirectoryStream`, the native Java equivalent of the operation the command performed, so no command string and no shell remain for an injection to target. Since the parameter is still used as a path, the replacement resolves it against a fixed base directory, normalises it, and rejects anything escaping that base, so closing the command injection does not introduce a path traversal.
