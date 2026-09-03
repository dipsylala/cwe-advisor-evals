## Verdict

Exploitable

## Source

User input from `request.getParameter("name")` in Case04A.java (line 16), passed to Case04B.handleSink() as the `data` parameter.

## Fix

**Vulnerable code (Case04B.java, lines 14-28):**
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

**Fixed code:**
```java
import java.nio.file.*;
import java.util.stream.Stream;

public void handleSink(String data, HttpServletRequest request, HttpServletResponse response) throws Throwable
{
    // Use Java's Files API to list directory instead of os commands
    try (Stream<Path> paths = Files.list(Paths.get("."))) {
        paths.forEach(path -> {
            // Safe directory listing - no command injection possible
            // Process the path as needed
            System.out.println(path);
        });
    } catch (IOException e) {
        // Handle error appropriately
        throw new RuntimeException("Directory listing failed", e);
    }
}
```

## Explanation

The original code concatenates untrusted user input directly into an operating system command string and executes it via `Runtime.exec()`. An attacker can inject arbitrary shell commands by providing input like `"; malicious_command"` which will be executed by the shell interpreter. The fix eliminates the OS command execution entirely by replacing it with Java's native `Files.list()` API from `java.nio.file`, which performs directory listing safely without invoking a shell or concatenating user input. Since the stated purpose of the code is to list directory contents, using the language-native file I/O API is both safer and more efficient than spawning external processes.

## Behaviour changes

- The original code spawned external processes (`cmd.exe /c dir` on Windows, `/bin/ls` on Unix) with separate exit codes and output streams; the fixed code uses Java's Files API which has no separate process or exit code.
- The original code's return value (the Process object) is eliminated since file listing is now handled by Java's stream API instead of process execution.
- Output handling changes from separate stdout/stderr streams accessed via `process.getInputStream()/getErrorStream()` to a stream of Path objects; the calling code must adapt to consume the stream as needed.
- The unused `data` parameter (which was the injection vulnerability) is no longer used in the fixed version; if validation or filtering of the `data` parameter is required by the caller, that logic must be added separately.
