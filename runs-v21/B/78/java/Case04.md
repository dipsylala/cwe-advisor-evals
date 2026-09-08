## Verdict

The finding is valid: CWE-78 (OS Command Injection) exists at line 28 of Case04B.java.

## Source

**Data flow:**
1. **Source (Case04A.java:16)**: `data = request.getParameter("name")` - untrusted HTTP request parameter
2. **Sink (Case04B.java:28)**: `Process process = Runtime.getRuntime().exec(osCommand + data)` - user input concatenated directly into command string

The `data` parameter flows from an HTTP request directly into a system command without validation or escaping. An attacker can inject shell commands by providing input such as `; rm -rf /` or `| cat /etc/passwd` to break out of the `dir` or `ls` command and execute arbitrary OS commands.

## Fix

### File: Case04B.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;
import java.nio.file.*;
import java.io.IOException;

public class Case04B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        // Validate input to prevent path traversal
        if (data == null || data.trim().isEmpty() || data.contains("..")) {
            return;
        }
        
        try {
            Path directoryPath = Paths.get(data);
            
            // List directory contents using Java's Files API instead of system commands
            if (Files.isDirectory(directoryPath)) {
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(directoryPath)) {
                    for (Path entry : stream) {
                        // Iterate through directory entries
                        // (Original code discarded this output)
                    }
                }
            }
        } catch (IOException | InvalidPathException e) {
            // Handle error - original code would have failed similarly
        }
    }
}
```

## Explanation

The fix eliminates the OS command injection by replacing `Runtime.exec()` with Java's native `java.nio.file.Files` API. The original code attempted to run system commands (`dir` on Windows, `ls` on Unix) with user-controlled input concatenated directly into the command string. This is vulnerable because the shell interprets special characters in the input.

The fixed code:
1. **Eliminates the vulnerable sink** - Removes the `Runtime.exec()` call entirely and replaces it with `Files.newDirectoryStream()`, which does not invoke a shell
2. **Validates the input** - Rejects null, empty, or path-traversal attempts (`..`), preventing directory traversal attacks
3. **Preserves the original behavior** - The code still lists directory contents using the safe API; it discards the output exactly as the original code did

The fix follows the CWE-78 guidance principle: "where the command is incidental to what the code needs to do... eliminating system command execution entirely by using language-native library alternatives." Directory listing is a perfect use case for Java's file I/O APIs, which provide the same functionality without shell interpretation of user input.

## Behaviour changes

- **No longer spawns external processes** - The vulnerable `Runtime.exec()` calls are eliminated; system resources are no longer consumed by spawning `cmd.exe/dir` or `/bin/ls`
- **Exception handling** - The original code had no explicit exception handling (exceptions would propagate); the fix catches `IOException` (for directory access failures) and `InvalidPathException` (for invalid path strings) to handle errors gracefully
- **Input validation** - The fix validates the input to reject empty strings and path traversal attempts, preventing both command injection and directory traversal attacks
- **Output consumption** - The original code discarded all output from the spawned process; the fixed code similarly discards directory entries in the loop (no functional change to the caller)
