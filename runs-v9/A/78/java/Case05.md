## Verdict

Confirmed. `Case05D.handleSink` builds an OS command by concatenating an attacker-controlled string directly onto a fixed command prefix and passes the result to `Runtime.getRuntime().exec(String)`, which on Windows tokenizes the whole string through `cmd.exe /c`. An attacker who controls `data` can append shell metacharacters (`&`, `|`, `;`, backtick, etc. depending on platform) to run arbitrary additional commands.

## Source

`request.getParameter("name")` in `Case05A.handle` (Case05A.java, line 16). This value flows unmodified as the `data` parameter through `Case05B.handleSink` -> `Case05C.handleSink` -> `Case05D.handleSink`, with no validation, sanitization, or encoding at any hop.

## Fix

In `Case05D.java`, replace the string-concatenation `Runtime.getRuntime().exec(osCommand + data)` call with a `ProcessBuilder` invocation that passes the directory listing target as a separate argument, never as part of a shell-interpreted string, and validate `data` before it is used:

```java
package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class Case05D
{
    public void handleSink(String data, HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        // Resolve the requested target under a fixed base directory so the value
        // cannot escape via ".." or an absolute path, and cannot be interpreted
        // as a command-line flag (it no longer starts with the raw user string).
        File baseDir = new File("/var/app/listable").getCanonicalFile();
        File requested = new File(baseDir, data == null ? "." : data);
        File target = requested.getCanonicalFile();

        if (!target.getPath().startsWith(baseDir.getPath() + File.separator)
                && !target.equals(baseDir))
        {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid target");
            return;
        }

        boolean isWindows = System.getProperty("os.name").toLowerCase().indexOf("win") >= 0;

        List<String> command = new ArrayList<>();
        if (isWindows)
        {
            command.add("c:\\WINDOWS\\SYSTEM32\\cmd.exe");
            command.add("/c");
            command.add("dir");
            command.add(target.getAbsolutePath());
        }
        else
        {
            command.add("/bin/ls");
            command.add("--");
            command.add(target.getAbsolutePath());
        }

        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        process.waitFor();
    }
}
```

Key changes:

- `Runtime.exec(String)` is replaced with `ProcessBuilder(List<String>)`. Each argument is passed as its own array element to the OS process directly, so no shell ever re-parses a concatenated string and shell metacharacters in `data` lose their special meaning.
- `data` is resolved against a fixed base directory with `File.getCanonicalFile()` and checked to still be inside that base directory, closing directory-traversal (`..`) alongside the injection issue rather than just the injection alone.
- On the non-Windows path, `--` is inserted before the resolved path so `/bin/ls` treats it strictly as a positional operand, not as an option, even if the resolved value could otherwise start with `-`.
- The Windows branch still shells out through `cmd.exe /c dir` (required because `dir` is a shell built-in, not a standalone executable), but because the path is now one argument in the array rather than part of a concatenated command line, `cmd.exe` receives it as a single token and it can no longer be used to append `&`, `|`, or additional commands.

## Explanation

The root cause is untrusted input (`request.getParameter("name")`) reaching a command-execution sink (`Runtime.exec`) after simple string concatenation, with the raw value crossing three intermediate method calls (`Case05B`, `Case05C`) that pass it through unchanged. Because `Runtime.exec(String)` tokenizes its argument and, on Windows, is invoked via `cmd.exe /c`, any shell metacharacters in the "name" parameter are interpreted rather than treated as literal data, letting an attacker chain in a second command. Switching to `ProcessBuilder` with a pre-built argument list removes the shell re-interpretation step for argument separation, and constraining the resolved path to a fixed base directory (plus the `--` end-of-options marker on the Unix branch) closes both the command-injection and path-traversal variants of this finding without changing the servlet's intended behavior of listing a requested directory.
