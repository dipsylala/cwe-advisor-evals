## Verdict

Exploitable. Untrusted HTTP request parameter flows through the call chain to line 28 of Case05D.java, where it is concatenated into an OS command string without validation and passed to Runtime.getRuntime().exec(). An attacker can inject arbitrary OS commands by including shell metacharacters (e.g., `; rm -rf /` or `& taskkill /F /IM svchost.exe`) in the request parameter.

## Source

HTTP servlet request parameter "name" obtained at Case05A.java line 16:
```
data = request.getParameter("name");
```

Taint flows through method call chain:
- Case05A → Case05B → Case05C → Case05D

## Fix

**Vulnerable Code (Case05D.java):**
```java
String osCommand;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
    osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
} else {
    osCommand = "/bin/ls ";
}

// SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
Process process = Runtime.getRuntime().exec(osCommand + data);
process.waitFor();
```

**Fixed Code (Case05D.java):**
```java
import java.nio.file.*;
import java.io.IOException;

public void handleSink(String data, HttpServletRequest request, HttpServletResponse response) throws Throwable {
    try {
        // Validate and construct path from untrusted input
        Path targetPath = Paths.get(data).toAbsolutePath();
        
        // Verify path exists and is a directory
        if (!Files.isDirectory(targetPath)) {
            throw new IllegalArgumentException("Not a directory");
        }
        
        // List directory contents using Java API instead of OS command
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(targetPath)) {
            for (Path entry : stream) {
                // Process entries as needed
            }
        }
    } catch (IOException | InvalidPathException e) {
        throw new Throwable("Directory listing failed", e);
    }
}
```

## Explanation

The original code attempted to list directory contents by executing platform-specific OS commands (cmd.exe /c dir on Windows, /bin/ls on Unix) with user-supplied path input concatenated into the command string. This is vulnerable to OS command injection because special characters in the input (`;`, `|`, `&`, backticks, `$()`, etc.) are interpreted as shell syntax rather than literal path components.

The fix replaces Runtime.exec() with Java's built-in java.nio.file.Files API, which provides native directory listing without shell interpretation. The untrusted input is validated as a valid file path and checked that it refers to an actual directory before attempting to list it. By eliminating OS command execution entirely, the injection point is removed and the code gains the benefits of proper exception handling for invalid paths.

## Behaviour changes

- **Replaces**: OS process invocation with Java standard library call
- **New exception type**: InvalidPathException for malformed paths (previously wrapped in RuntimeException from exec)
- **Validation added**: Path existence and directory type check (prevents listing non-directories)
- **Output not captured**: Original code did not capture stdout/stderr; fixed code similarly does not introduce output capture
- **Error handling**: IOException now caught explicitly instead of propagating as process exit code
- **Return value preservation**: Original method returned void (only awaited process completion); fixed method maintains void return and similar completion semantics via successful iteration or exception on failure
