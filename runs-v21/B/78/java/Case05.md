## Verdict

exploitable

## Source

`request.getParameter("name")` in Case05A.handleSink() - untrusted HTTP request parameter

## Fix

### File: Case05D.java

```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.io.IOException;

public class Case05D
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        try {
            // Replace OS command execution with Java's file listing API
            // to eliminate the command injection vulnerability
            Files.list(Paths.get(data))
                .forEach(p -> System.out.println(p.getFileName()));
        } catch (InvalidPathException e) {
            System.err.println("Invalid path: " + data);
        } catch (IOException e) {
            System.err.println("Error listing directory: " + e.getMessage());
        }
    }
}
```

## Explanation

The vulnerability is caused by concatenating untrusted user input directly into an OS command string, which is then executed via `Runtime.exec()`. The fix replaces the OS command execution entirely with Java's native file listing API (`java.nio.file.Files.list()`). This eliminates the injection point by removing the shell invocation and command string concatenation. The `data` parameter is now interpreted as a file path only, not as part of a shell command, so command injection through shell metacharacters (such as `;`, `|`, or `&&`) is no longer possible. The path is validated by `Paths.get()` which throws `InvalidPathException` for invalid paths, and `Files.list()` throws `IOException` for non-existent or inaccessible directories, both of which are caught and logged safely without exposing system details.

## Behaviour changes

1. **No Process object returned**: The original code created and returned a Process object via `Runtime.exec()`. The fixed code uses Java APIs and does not return a Process object. The caller cannot access process exit codes or captured streams. This is acceptable because the original code did not capture or consume stdout/stderr anyway.

2. **Error handling differs**: The original code relied on OS error messages from `dir` or `ls`. The fixed code catches `InvalidPathException` for invalid paths and `IOException` for directory access failures, providing Java-level error handling instead of OS-level errors.

3. **Output format may differ**: The original code output whatever `dir` or `ls` produced (with all columns and formatting). The fixed code outputs only the file names via `Files.list()`, which is a simpler format. This is a trade-off to eliminate the security vulnerability.

4. **Input validation**: The fixed code validates the input path through Java's path handling (`Paths.get()` and `Files.list()`), which provides protection against invalid paths. The original code passed any string to the OS command.
