## Verdict

CONFIRMED - OS Command Injection via untrusted user input concatenated into Runtime.exec() call. Fix applies java.nio.file.Files API to replace command execution entirely.

## Source

User input originates in `Case05A.java` line 16:
```
data = request.getParameter("name");
```

Data flows through `Case05B` and `Case05C` (pass-throughs) to `Case05D`.

## Fix

### File: Case05D.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;
import java.nio.file.*;

public class Case05D
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        try {
            // Use Java's built-in file API instead of OS command execution
            Path baseDirectory = Paths.get(System.getProperty("user.dir"));
            Path targetPath = baseDirectory.resolve(data).normalize();
            
            // Validate that path does not escape base directory (path traversal protection)
            if (!targetPath.toAbsolutePath().startsWith(baseDirectory.toAbsolutePath())) {
                throw new IllegalArgumentException("Access denied: path traversal attempt");
            }
            
            // List directory contents using Java API instead of dir/ls command
            if (Files.exists(targetPath) && Files.isDirectory(targetPath)) {
                Files.list(targetPath)
                    .forEach(path -> System.out.println(path.getFileName()));
            }
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
    }
}
```

## Explanation

The original code executed OS commands (`cmd.exe /c dir` on Windows or `/bin/ls` on Unix) by concatenating untrusted user input directly into the command string passed to `Runtime.getRuntime().exec()`. This allows arbitrary command injection.

The fix eliminates the OS command execution entirely by replacing it with Java's native `java.nio.file.Files` API. The code now:

1. Converts the user input to a `Path` using `Paths.get()` and `Path.resolve()`
2. Normalizes the path with `normalize()` to resolve `.` and `..` sequences
3. Validates the path stays within the base directory to prevent path traversal attacks
4. Uses `Files.list()` to enumerate directory contents directly in Java, eliminating the injection point

This approach closes the injection vulnerability while preserving the original functionality (listing directory contents). The path traversal validation ensures attackers cannot use `../` sequences to escape the intended directory.

## Behaviour changes

1. **Output format**: Original code output the full path from `dir`/`ls`; fixed code outputs only filenames via `path.getFileName()`
2. **Error handling**: Original code threw `IOException` directly; fixed code wraps it in `RuntimeException` for consistency with declared exception handling
3. **Execution model**: Removed OS process creation entirely; directory enumeration now happens in-process via Java API, eliminating all command injection risk
4. **Path validation**: Added explicit bounds checking to prevent directory traversal; attempts to access paths outside the base directory throw `IllegalArgumentException`
5. **No process object**: Code no longer creates or returns a `Process` object (was not used in original anyway - `waitFor()` was called but result discarded)
