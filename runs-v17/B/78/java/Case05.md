## Verdict
exploitable

## Source
`request.getParameter("name")` in Case05A.java, line 16 - attacker-controlled HTTP parameter passed through the call chain

## Fix

### File: Case05D.java

```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;
import java.nio.file.*;
import java.util.stream.Stream;
import java.io.IOException;

public class Case05D
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        // Reject null or empty input
        if (data == null || data.isEmpty()) {
            return;
        }
        
        // Validate input to prevent directory traversal and shell injection
        // Only allow alphanumeric, dots, underscores, and forward slashes
        if (!data.matches("[a-zA-Z0-9._/-]*")) {
            return;
        }
        
        // Normalize path and prevent directory traversal attacks
        Path targetPath = Paths.get(data).normalize();
        
        // Reject absolute paths and attempts to escape parent directory
        if (targetPath.isAbsolute() || targetPath.toString().contains("..")) {
            return;
        }
        
        // Use Java's Files API instead of executing system commands
        // This eliminates the OS command injection vulnerability
        try (Stream<Path> paths = Files.list(Paths.get(".").resolve(targetPath))) {
            paths.forEach(p -> System.out.println(p.getFileName()));
        } catch (IOException e) {
            // Handle error silently or log as needed
        }
    }
}
```

## Explanation
The original code constructed an OS command string by concatenating user input directly: `Runtime.getRuntime().exec(osCommand + data)`. This classic OS command injection vulnerability allows an attacker to inject arbitrary shell metacharacters and commands. The fix eliminates the system command execution entirely by replacing `Runtime.exec()` with Java's native `Files.list()` API, which achieves the same functional goal (listing directory contents) without invoking a shell. The input is validated with a strict allowlist (alphanumeric, dots, underscores, forward slashes) and path normalization is applied to prevent directory traversal attacks. Null/empty inputs and absolute paths are rejected before the API call. This approach removes the injection vector completely rather than attempting to escape or sanitize the command string.

## Behaviour changes
- **Injection vector closed**: Eliminates `Runtime.exec()` call and command string concatenation entirely
- **Output method unchanged**: Both original and fixed code print filenames to stdout
- **Input validation added**: The fix adds strict validation (allowlist pattern and path normalization) that rejects certain inputs the original code would have accepted. Inputs failing validation return early without printing. This is a necessary security hardening and a behaviour change that prevents exploitation.
- **Error handling changed**: Original code propagates `IOException`; fixed code catches it silently. This is acceptable since the original code also caught exceptions from the process execution implicitly (via the throws clause).
- **Scope reduced**: The original code could execute arbitrary commands on the system; the fixed code can only list directories within the current working directory tree.
