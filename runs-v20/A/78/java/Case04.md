## Verdict

Confirmed. `Case04B.handleSink` builds an OS command string by concatenating a fixed prefix (`cmd.exe /c dir ` or `/bin/ls `) with an attacker-controlled value and passes the whole string to `Runtime.getRuntime().exec(String)`. On Windows, `cmd.exe /c` invokes a real shell over the remaining text, so request input can inject shell metacharacters (`&`, `|`, `&&`, etc.) to chain arbitrary commands.

## Source

`Case04A.handle` reads the untrusted value directly from the HTTP request:

```java
data = request.getParameter("name");
(new Case04B()).handleSink(data, request, response);
```

`data` flows unmodified into `Case04B.handleSink`, where it is concatenated onto the command string and reaches `Runtime.getRuntime().exec(...)` at the flagged line.

## Fix

### File: Case04B.java

```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;
import java.io.File;
import java.io.IOException;

public class Case04B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        // Resolve the requested entry against a fixed base directory and
        // verify the canonical result does not escape it, so a listing can
        // never be pointed outside the intended tree (including via an
        // absolute path supplied in "data").
        File baseDir = new File(".").getCanonicalFile();
        File target = (data == null || data.isEmpty())
                ? baseDir
                : new File(baseDir, data).getCanonicalFile();

        String basePath = baseDir.getPath();
        if (!target.getPath().equals(basePath) && !target.getPath().startsWith(basePath + File.separator)) {
            throw new IOException("Requested path is outside the allowed directory: " + data);
        }

        // List the directory contents directly through the Java runtime
        // instead of shelling out to "dir"/"ls" with a value built from
        // request input. This removes the external OS command entirely, so
        // there is no shell (cmd.exe /c on Windows) left for metacharacters
        // in the request parameter to reach.
        File[] entries = target.isDirectory() ? target.listFiles() : new File[] { target };
        if (entries != null)
        {
            for (File entry : entries)
            {
                System.out.println(entry.getName());
            }
        }
    }
}
```

## Explanation

The original code's vulnerability was the shell reached through `cmd.exe /c` on Windows: `Runtime.exec(String)` tokenizes the whole string on whitespace and hands `/c dir <data>` to `cmd.exe`, which then re-parses that text as a command line, so metacharacters inside `data` (`&`, `|`, `&&`) let an attacker append and run arbitrary commands. Building the argument as an array instead of a concatenated string would not have closed this gap, because `dir` is a `cmd.exe` built-in, not a standalone executable - any invocation that still routes through `cmd.exe /c` keeps the shell in the loop.

The fix removes the external process entirely and performs the directory listing with `java.io.File`, which is a native, in-process operation with no command-line parsing step, closing the injection on both platforms outright rather than trying to further sanitize the value passed to a shell. Because the requested name still selects which file or directory is listed, the fix also resolves it against a fixed base directory and rejects anything whose canonical path escapes that base - this uses `getCanonicalFile()` so an absolute path or a `..` sequence in `data` cannot walk the listing outside the intended tree, closing the related path-traversal angle rather than only the command-injection one.
