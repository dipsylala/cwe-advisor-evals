## Verdict
exploitable

## Source
`HttpServletRequest.getParameter("name")` in Case04A.java line 16 — untrusted user input from HTTP request parameter

## Fix

### File: Case04B.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Case04B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        // Replace OS command execution with native Java file API
        Path targetPath = Paths.get(data);
        
        try (java.util.stream.Stream<Path> paths = Files.list(targetPath))
        {
            paths.forEach(path -> System.out.println(path.getFileName()));
        }
    }
}
```

## Explanation

The original code executed OS commands (`dir` on Windows, `ls` on Unix) by concatenating untrusted user input directly into the command string, enabling OS command injection. The fix eliminates the `Runtime.exec()` call entirely by replacing it with `java.nio.file.Files.list()`, which is the language-native equivalent for directory listing operations. The data parameter now specifies a filesystem path directly, avoiding shell interpretation altogether. The try-with-resources statement ensures proper resource cleanup of the stream. This eliminates the injection point while preserving the directory listing functionality.

## Behaviour changes

The output format changes: the original code executed a system command whose output was handled elsewhere (captured by the process descriptor); the fixed code prints directory entries to stdout. This is a necessary trade-off when eliminating the command execution. If the response needs to be written to `response` instead of stdout, use `response.getWriter().println(path.getFileName())` instead of `System.out.println()`, which is a localized change to the output destination without affecting the injection fix.

