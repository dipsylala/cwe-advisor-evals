## Verdict

**Exploitable.** Untrusted HTTP request parameter is concatenated directly into an OS command string and executed without validation.

## Source

Line 16, Case06A.java:
```java
data = request.getParameter("name");
```

The `data` parameter flows unvalidated through Case06B, Case06C, and Case06D to the sink.

## Fix

Replace `Runtime.getRuntime().exec()` with Java's native file I/O API:

```java
public void handleSink(String data, HttpServletRequest request, HttpServletResponse response) throws Throwable
{
    Path directory = Paths.get(data);
    
    try (Stream<Path> paths = Files.list(directory)) {
        paths.forEach(path -> {
            // Process each path in the directory
            System.out.println(path.getFileName());
        });
    } catch (IOException e) {
        // Handle I/O error
        throw new ServletException("Failed to list directory", e);
    }
}
```

Add imports at the top of Case06E.java:
```java
import java.nio.file.*;
import java.util.stream.Stream;
import javax.servlet.ServletException;
```

## Explanation

The original code executes OS commands (`dir` on Windows, `ls` on Unix) to list directory contents, but concatenates untrusted user input directly into the command string. This allows an attacker to inject arbitrary commands (e.g., `name=../../../..;cat /etc/passwd`).

The fix eliminates OS command execution entirely by using `Files.list()`, a Java standard library method that performs directory listing natively. This removes the injection vector while preserving the same functionality. The solution:

1. Reads the `data` parameter as a directory path (not a command argument)
2. Uses `java.nio.file.Files.list()` to enumerate directory contents safely
3. Handles IOException for invalid paths or access errors
4. Returns the same information the original command provided (directory listing)

No external libraries are required—this uses only JDK standard APIs available since Java 7.

## Behaviour changes

- **Command execution eliminated**: No more `Runtime.exec()` or shell invocation (`cmd.exe`, `/bin/ls`)
- **Output handling**: Original code called `waitFor()` but discarded process output; fixed code explicitly processes each directory entry via the Stream, making the intent clear and preventing information leaks
- **Error handling**: Invalid paths throw `IOException` caught and wrapped in ServletException, replacing the unchecked IOException from the original
- **Functionality preserved**: Both versions enumerate directory contents; fixed version returns file paths via Stream processing instead of subprocess stdout
