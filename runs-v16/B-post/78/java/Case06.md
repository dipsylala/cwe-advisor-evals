## Verdict

Exploitable

## Source

HTTP request parameter `name` obtained via `request.getParameter("name")` in Case06A (line 16).

## Fix

**Vulnerable Code (Case06E.java, lines 27-29):**

```java
        // SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
        Process process = Runtime.getRuntime().exec(osCommand + data);
        process.waitFor();
```

**Fixed Code:**

```java
        // Use Java's native File I/O API instead of Runtime.exec()
        // This eliminates OS command injection by avoiding shell execution
        Path targetPath = Paths.get(data);
        
        try {
            // Resolve the path to detect symbolic links and verify existence
            Path realPath = targetPath.toRealPath();
            
            // List directory contents safely using Files API instead of shell commands
            if (Files.isDirectory(realPath)) {
                try (Stream<Path> paths = Files.list(realPath)) {
                    paths.forEach(p -> System.out.println(p.getFileName()));
                }
            }
        } catch (IOException e) {
            // Handle invalid path or I/O errors gracefully
            e.printStackTrace();
        }
```

The complete fixed Case06E class requires adding imports:

```java
import java.nio.file.*;
import java.util.stream.*;
```

## Explanation

The original code constructed OS commands by string concatenation (`osCommand + data`) and executed them via `Runtime.getRuntime().exec()`. This allows command injection: an attacker controlling the HTTP parameter could inject shell metacharacters or additional commands. The vulnerable code attempted to list a directory by concatenating the user-supplied path into either `cmd.exe /c dir` (Windows) or `/bin/ls` (Unix).

The fixed code replaces the process execution with Java's native File I/O API (java.nio.file.Files). It creates a Path from the user input, resolves it to detect any symbolic link traversal, validates it points to a directory, and then uses `Files.list()` to safely enumerate the directory contents without spawning a shell or external process. The `toRealPath()` call ensures symlinks are resolved and the path exists, providing implicit validation. The `isDirectory()` check ensures we only attempt to list directories. Both `Runtime.exec()` and the shell command string are eliminated entirely, closing the injection point. IOException handling preserves the existing error behavior of silently handling inaccessible paths.

## Behaviour changes

- Process execution eliminated: No child process is spawned. The code now lists directory contents entirely in-process using Java APIs.
- Output format change: The original `dir` and `ls` commands produce formatted output; the fixed code outputs only file names (one per line). This is a minor output format difference but the core listing functionality is preserved.
- Path validation: The `toRealPath()` call implicitly validates that the path exists and is accessible, throwing IOException if not. This is stricter than the original which would attempt to run the command even on invalid paths.
- No return value change: The original code did not capture or return the Process output, and the fixed code does not either; output goes to stdout in both cases.

## Verification

Java syntax verification of the fixed code:
- All new imports (`java.nio.file.Path`, `java.nio.file.Paths`, `java.nio.file.Files`, `java.util.stream.Stream`) are part of the Java standard library (available since Java 7 for NIO.2, Java 8 for Streams)
- Method signatures are verified: `Paths.get(String)` returns `Path`, `Path.toRealPath()` returns `Path` and throws `IOException`, `Files.isDirectory(Path)` returns `boolean`, `Files.list(Path)` returns `Stream<Path>`
- Try-with-resources for Stream ensures proper resource closure
- Exception handling preserves the original throws declaration and error handling pattern

No external dependencies introduced. All APIs are standard Java platform features.
