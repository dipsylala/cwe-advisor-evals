## Verdict

Confirmed. `Case04B.handleSink()` builds an OS command line by string-concatenating untrusted input and hands it to `Runtime.getRuntime().exec()`, which is a classic OS Command Injection (CWE-78).

## Source

- `Case04A.handle()` (Case04A.java:16) reads the untrusted value directly from the HTTP request: `data = request.getParameter("name");`
- That value is passed unchanged into `Case04B.handleSink(data, request, response)` (Case04A.java:18).
- `Case04B.handleSink()` concatenates it onto a hard-coded command prefix — `cmd.exe /c dir ` on Windows or `/bin/ls ` otherwise (Case04B.java:14-24) — and executes the result with `Runtime.getRuntime().exec(osCommand + data)` (Case04B.java:28).

On the Windows branch this is directly exploitable: `cmd.exe` is invoked as an explicit interpreter with `/c`, and everything after it is re-parsed by `cmd.exe` as a full command line, so shell metacharacters in `data` (`&`, `&&`, `|`, `>`, etc.) let an attacker chain arbitrary additional commands. On the non-Windows branch, Java's `Runtime.exec(String)` tokenizes on whitespace and invokes `/bin/ls` directly without a shell, but attacker-controlled whitespace still lets extra arguments/flags be injected into `ls`, and unvalidated input reaching a process-execution API is the reportable weakness regardless of platform.

## Fix

Eliminate the string-built command and the shell hand-off. Two changes, both needed:

1. **Stop shelling out for a directory listing.** The intent of this code is just to list a directory. Do it with Java's own I/O APIs instead of spawning `dir`/`ls`, which removes the injection surface entirely:

```java
package evalcases;

import javax.servlet.http.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.regex.Pattern;

public class Case04B
{
    private static final Path BASE_DIR = Paths.get("/var/app/listable").toAbsolutePath().normalize();
    private static final Pattern SAFE_NAME = Pattern.compile("^[A-Za-z0-9_-]{1,64}$");

    public void handleSink(String data, HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        if (data == null || !SAFE_NAME.matcher(data).matches())
        {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid name");
            return;
        }

        Path target = BASE_DIR.resolve(data).normalize();
        if (!target.startsWith(BASE_DIR) || !Files.isDirectory(target))
        {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid name");
            return;
        }

        try (DirectoryStream<Path> entries = Files.newDirectoryStream(target))
        {
            for (Path entry : entries)
            {
                response.getWriter().println(entry.getFileName());
            }
        }
        catch (IOException e)
        {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}
```

2. **If a native process genuinely must be invoked** (this pattern applies wherever exec cannot be avoided), never build the command as a single interpreter string:
   - Use `ProcessBuilder` with a fixed program and a `List<String>`/`String[]` argument vector, so each argument is passed to the OS as a discrete token instead of being re-parsed by a shell.
   - Never put `cmd.exe /c` (or `/bin/sh -c`) in front of an argument list that contains attacker-influenced data — that reintroduces exactly the re-parsing this fix removes.
   - Still validate `data` against a strict allowlist (as above) before using it as an argument, since an argument array closes shell-metacharacter injection but not option/flag injection (e.g. a value starting with `-`); reject values with a leading `-` or resolve them under a fixed base path first.

## Explanation

The vulnerability exists because attacker-controlled input (`request.getParameter("name")`) reaches `Runtime.getRuntime().exec()` by direct string concatenation, with no validation, encoding, or allowlisting anywhere on the path from source to sink. On Windows, `cmd.exe` is explicitly named as the interpreter, so the appended `data` is parsed by the shell itself — an attacker can submit a value such as `& net user hacker Passw0rd! /add` and have it executed as a second command. The fix removes the interpreter from the picture altogether by performing the directory listing with Java's own filesystem API, which cannot be coerced into running arbitrary commands. The added allowlist check (`^[A-Za-z0-9_-]{1,64}$`) and `startsWith(BASE_DIR)` containment check also close a path-traversal avenue (e.g. `../../etc`) that would otherwise survive even after the shell is removed. For any case where a genuine external process is unavoidable, the same input must be passed as a separate `ProcessBuilder` argument rather than appended to a command string, and still validated, since an argument vector prevents shell metacharacter injection but not flag/option injection via a leading `-`.
