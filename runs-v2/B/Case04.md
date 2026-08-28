## Verdict

exploitable

## Source

Untrusted data enters at `e:/Github/cwe-advisor/evals/cases-v2/Case04/Case04A.java` line 16, `data = request.getParameter("name")` - an attacker-controlled HTTP query/form parameter.

Path to the sink:

- `Case04A.java:16` - `data` assigned from `request.getParameter("name")`.
- `Case04A.java:18` - `data` passed unchanged to `(new Case04B()).handleSink(data, request, response)`.
- `Case04B.java:11` - received as the `data` parameter; no validation, encoding, or reassignment occurs.
- `Case04B.java:28` (sink) - concatenated into the command string and executed: `Runtime.getRuntime().exec(osCommand + data)`.

No sanitiser, allowlist, or length/character check appears anywhere on the path, so the taint reaches the sink intact.

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

public class Case04B
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

The command being built was a directory listing (`cmd.exe /c dir` on Windows, `/bin/ls` otherwise) with the request parameter appended to it, so anything the attacker supplied became part of a shell command line - on Windows the `cmd.exe /c` prefix lets `&`, `|`, or `&&` chain arbitrary commands, and even without a shell `Runtime.exec(String)` tokenises the concatenated string so the value is re-split into further arguments. The fix removes process execution entirely and performs the listing with `java.nio.file.Files.newDirectoryStream`, which is the native Java equivalent of the operation the command was performing; with no command string and no shell there is no injection point left, regardless of what the parameter contains. Because the parameter is still used as a path, the replacement also resolves it against a fixed base directory, normalises it, and rejects anything that escapes that base, so eliminating the command injection does not open a path traversal in its place.
