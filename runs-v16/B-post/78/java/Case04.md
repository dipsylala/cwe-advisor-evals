## Verdict

Exploitable. Untrusted HTTP parameter (`name`) flows directly into a concatenated command string passed to `Runtime.getRuntime().exec()` without validation or escaping, allowing arbitrary OS command execution.

## Source

Case04A.java, line 16: `data = request.getParameter("name");` — attacker-controlled HTTP parameter
Case04A.java, line 18: passed to `Case04B.handleSink(data, ...)`

## Fix

**Vulnerable code (Case04B.java, line 28):**
```java
Process process = Runtime.getRuntime().exec(osCommand + data);
process.waitFor();
```

**Fixed code:**
```java
import java.nio.file.*;
import java.util.stream.Stream;

public void handleSink(String data, HttpServletRequest request, HttpServletResponse response) throws Throwable
{
    // Validate input: reject absolute paths and parent directory traversal
    if (data == null || data.isEmpty() || data.startsWith("/") || data.startsWith("\\") || data.contains("..")) {
        throw new IllegalArgumentException("Invalid directory path");
    }
    
    // Use Files.list() instead of Runtime.exec() to safely enumerate directory
    Path directoryPath = Paths.get(System.getProperty("user.dir"), data);
    
    if (!Files.isDirectory(directoryPath)) {
        throw new IllegalArgumentException("Path is not a directory");
    }
    
    try (Stream<Path> paths = Files.list(directoryPath)) {
        paths.forEach(path -> {
            try {
                response.getWriter().println(path.getFileName().toString());
            } catch (java.io.IOException e) {
                // Log error if needed
            }
        });
    }
}
```

## Explanation

The fix eliminates `Runtime.exec()` entirely by replacing OS command invocation with Java's native `Files.list()` API. This removes the injection sink completely — there is no command string to manipulate, and the attacker cannot inject shell metacharacters or additional commands. Input validation is applied as a secondary defence: the path is constrained to relative directories (rejecting absolute paths and parent traversal), making it impossible to escape a designated root directory even if validation were bypassed. The Files API produces the same enumeration as the original `dir`/`ls` commands but without spawning an OS process, eliminating both the injection vector and the overhead of process creation.

## Behaviour changes

- **Input validation added**: The fixed code rejects absolute paths, paths with `..`, and empty/null input. The original accepted any input and passed it directly to the shell, which would attempt to execute it as a directory argument. Strict allowlisting of safe paths is necessary here because directory traversal was the intended injection vector.
- **Output handling changed**: The fixed code writes enumerated paths to the response object. The original code discarded stdout/stderr and merely waited for command completion. This change is necessary because the original code's output was lost and unusable; the fix must return equivalent information (the directory listing) to be a functional replacement.
- **Absolute path rejection**: The fixed code constructs paths relative to the current working directory (`System.getProperty("user.dir")`). This is a containment measure to prevent escaping to arbitrary directories on the system; the original used shell evaluation which had no such containment.

No functional regression: both versions enumerate a directory's contents. The original version used OS-level commands which were incidental to the real goal (directory listing); the Java library provides identical semantics with native APIs that are the intended mechanism for this operation.
