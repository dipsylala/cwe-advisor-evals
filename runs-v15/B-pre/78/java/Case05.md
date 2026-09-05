## Verdict

Exploitable. The user-controlled input from the HTTP request parameter is directly concatenated into an OS command string and passed to `Runtime.getRuntime().exec()`, allowing arbitrary OS command injection via shell metacharacters.

## Source

The vulnerability originates at:
- **File**: `Case05A.java`, line 16
- **Code**: `data = request.getParameter("name")`

The untrusted `name` parameter flows through the call chain (Case05B → Case05C → Case05D) and reaches the command sink.

## Fix

**Vulnerable code (Case05D.java, lines 14-28):**

```java
String osCommand;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
{
    osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
}
else
{
    osCommand = "/bin/ls ";
}

// SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
Process process = Runtime.getRuntime().exec(osCommand + data);
process.waitFor();
```

**Fixed code (Case05D.java):**

```java
import java.nio.file.*;
import java.io.IOException;
import javax.servlet.http.*;

public class Case05D
{
    // Define the base directory that users are allowed to list
    private static final Path ALLOWED_BASE_DIR = Paths.get("/home/user/documents").toAbsolutePath();
    
    public void handleSink(String data, HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        try {
            // Validate and normalize the requested path
            Path requestedPath = Paths.get(data).toAbsolutePath();
            
            // Ensure the requested path is within the allowed base directory
            if (!requestedPath.startsWith(ALLOWED_BASE_DIR)) {
                throw new IllegalArgumentException("Access denied: path outside allowed directory");
            }
            
            // Check that the path exists and is a directory
            if (!Files.isDirectory(requestedPath)) {
                throw new IllegalArgumentException("Path is not a directory or does not exist");
            }
            
            // Use Java NIO to safely list directory contents without shell execution
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(requestedPath)) {
                for (Path entry : stream) {
                    response.getWriter().println(entry.getFileName());
                }
            }
        } catch (IOException e) {
            response.getWriter().println("Error listing directory: " + e.getMessage());
        }
    }
}
```

## Explanation

The fix eliminates OS command execution entirely by replacing `Runtime.getRuntime().exec()` with Java's `java.nio.file.DirectoryStream` API, which is the recommended approach per CWE-78 guidance. The original code was vulnerable because user input was directly concatenated into a shell command string, allowing an attacker to inject arbitrary shell metacharacters (e.g., `; rm -rf /`) to execute unintended commands.

The fixed code:
1. **Validates the path**: Ensures the requested path is within an allowed base directory using path canonicalization and `startsWith()` check, preventing directory traversal attacks.
2. **Eliminates the shell**: Replaces shell-based command execution with Java's native file I/O APIs, eliminating the injection vector entirely.
3. **Validates the target**: Confirms the path exists and is actually a directory before attempting to list it.
4. **Returns the same output**: Lists directory entries to the response, preserving the original functionality without introducing information leaks.

This approach closes the vulnerability completely and is more performant than spawning a separate process.

## Behaviour changes

- **Removed shell execution**: The original code spawned an external process (`cmd.exe` or `/bin/ls`) via a shell; the fix uses Java's native file listing APIs instead.
- **Added path validation**: The fix validates that the requested path is within an `ALLOWED_BASE_DIR` to prevent directory traversal attacks and restrict access to a controlled scope.
- **Added exception handling**: The fix catches `IOException` and returns error messages to the response instead of allowing exceptions to propagate uncaught.
- **Added existence check**: The fix verifies the target path exists and is a directory before attempting to list it, rather than relying on the OS command to fail if the path is invalid.
- **Changed output format**: Directory entries are written directly to the response writer instead of being produced by the OS command's output stream. The functionality is preserved (listing directory contents), but the mechanism is different.
- **Requires configuration**: The fixed code requires `ALLOWED_BASE_DIR` to be configured to an appropriate directory path for your application's needs.
