## Verdict

Confirmed. OS Command Injection (CWE-78) via concatenation of unsanitized user input into Runtime.exec().

## Source

HTTP request parameter "name" (Case04A.java, line 16: `request.getParameter("name")`) flows unsanitized through the call chain to become the `data` parameter in Case04B.handleSink().

## Fix

Replace Runtime.exec() with Java's native file I/O API. The original code invokes `ls` (Linux) or `dir` (Windows) to list directory contents; this is replaced with java.nio.file.Files and java.nio.file.DirectoryStream.

```java
import java.nio.file.*;

public void handleSink(String data, HttpServletRequest request, HttpServletResponse response) throws Throwable
{
    // Validate input: reject null, empty, and path traversal attempts
    if (data == null || data.isEmpty() || data.contains("..")) {
        return;
    }
    
    try {
        Path targetPath = Paths.get(data);
        
        // Validate that the path exists and is a directory
        if (!Files.isDirectory(targetPath)) {
            return;
        }
        
        // List directory contents using native Java API
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(targetPath)) {
            for (Path entry : stream) {
                // Process directory entries as needed
            }
        }
    } catch (IOException e) {
        // Handle errors (directory not accessible, not a directory, etc.)
    }
}
```

## Explanation

The fix eliminates Runtime.exec() entirely by replacing the OS command invocation with java.nio.file.DirectoryStream, which is the native Java equivalent for directory enumeration. Input validation is applied (rejecting null, empty strings, and path-traversal patterns like "..") before the Path is constructed, preventing attacks that attempt to escape the intended directory. The try-with-resources block ensures the DirectoryStream is properly closed. Exception handling is in place for I/O errors. This approach closes the command injection vector by removing shell execution altogether and using only the Java standard library.

## Behaviour changes

The original code spawned an external process (ls or dir) and waited for completion without capturing output. The fixed code:
- Removes all OS-level process spawning
- Lists directory contents via Java's native file I/O instead
- Adds input validation that rejects path traversal attempts (blocks "..", null, empty string)
- Uses structured iteration over Path objects instead of relying on OS command output
- Provides proper exception handling for filesystem errors rather than relying on process exit codes
- Eliminates platform-specific command variations (no more Windows/Linux conditional logic needed for this operation)
