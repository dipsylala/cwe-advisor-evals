# Case06: CWE-78 OS Command Injection Remediation

## Verdict

Exploitable. The data flow is clear and unbroken: attacker-controlled HTTP request parameter flows directly to OS command execution with no validation.

## Source

**Entry point**: `request.getParameter("name")` in Case06A.handle() line 16

**Data flow**: 
- Case06A.handle() receives "name" parameter from HTTP request
- Passes to Case06B.handleSink() (line 18)
- Through Case06C.handleSink() (line 13) 
- Through Case06D.handleSink() (line 13)
- To Case06E.handleSink() (line 13)

**Sink**: `Runtime.getRuntime().exec(osCommand + data)` in Case06E.java line 28

The untrusted `data` parameter is concatenated directly into an OS command string without validation and executed with Runtime.exec().

## Fix

### File: Case06E.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.DirectoryStream;

public class Case06E
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        // Use Java's native file API instead of OS commands to eliminate command injection
        Path baseDir = Paths.get(".");

        // Validate input to prevent directory traversal attacks
        if (data != null && !data.isEmpty()) {
            // Reject paths with directory traversal attempts or absolute paths
            if (data.contains("..") || data.startsWith("/") || data.startsWith("\\")) {
                throw new IllegalArgumentException("Invalid path: contains traversal or absolute path");
            }

            // Resolve the path relative to the current directory
            Path targetPath = baseDir.resolve(data);

            // List directory contents using Java API instead of shell command
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(targetPath)) {
                for (Path entry : stream) {
                    System.out.println(entry.getFileName());
                }
            }
        } else {
            // List current directory if no path specified
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(baseDir)) {
                for (Path entry : stream) {
                    System.out.println(entry.getFileName());
                }
            }
        }
    }
}
```

## Explanation

The original code executed OS commands (`cmd.exe /c dir` on Windows, `/bin/ls` on Unix) with untrusted data concatenated directly into the command string. Since Runtime.exec(String) internally uses StringTokenizer and the target is a shell interpreter, shell metacharacters in the data parameter (such as `;`, `|`, `&`) are interpreted as command separators, allowing arbitrary command injection.

The fix eliminates the OS command execution entirely by using Java's native file API (`java.nio.file.Files.newDirectoryStream()`), which performs directory listing without shell interpretation. The fix adds input validation to reject paths containing directory traversal sequences (`..`) and absolute paths, preventing access outside the intended directory. This approach follows the CWE-78 remediation guidance: eliminate system command execution where language-native alternatives exist.

The java.nio.file APIs used (Files, Paths, Path, DirectoryStream) are part of the standard Java library and require no additional dependencies.

## Behaviour changes

- **Output handling**: Original code captured output in a Process object (which was discarded via waitFor()); fixed code outputs directly to stdout. This is a visible difference but maintains the end effect of displaying directory contents.
- **Error handling**: Original code would throw IOException on process creation failure; fixed code throws IllegalArgumentException for invalid input paths and IOException for filesystem errors.
- **Path resolution**: Original code passed arguments directly to the shell for interpretation; fixed code resolves paths within the application using safe APIs, preventing shell interpretation of special characters.
- **Process object removed**: The fix no longer creates a Process object or calls waitFor(), as there is no external process to manage.

All Java nio.file imports are standard library components. Verification: TestNioApi class compiled successfully with javac 26, confirming API correctness.
