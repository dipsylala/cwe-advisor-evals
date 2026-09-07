## Verdict

exploitable

## Source

`data` parameter from HTTP request in Case05A.java line 16: `request.getParameter("name")`. The untrusted user input flows through the call chain (Case05A → Case05B → Case05C → Case05D) without validation or sanitization.

## Fix

**Vulnerable Code (Case05D.java, lines 14-29):**

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
Process process = Runtime.getRuntime().exec(osCommand + data);  // VULNERABLE: string concatenation
process.waitFor();
```

**Fixed Code (Case05D.java):**

```java
import java.nio.file.*;
import java.io.IOException;

// ...
// In handleSink method, replace the Runtime.exec() block:

try {
    // Validate input to prevent path traversal and null reference
    if (data == null || data.isEmpty() || data.contains("..") || data.startsWith("-")) {
        throw new IllegalArgumentException("Invalid path parameter");
    }
    
    // Use Java NIO API instead of OS command
    Path targetPath = Paths.get(data).toAbsolutePath().normalize();
    
    // Verify the path exists before attempting to list
    if (Files.exists(targetPath)) {
        if (Files.isDirectory(targetPath)) {
            // List directory contents using native Java API
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(targetPath)) {
                for (Path entry : stream) {
                    // Process each directory entry
                    // (In the original code, output was not used, so we iterate to simulate the operation)
                }
            }
        } else if (Files.isRegularFile(targetPath)) {
            // Handle file case if needed
        }
    }
} catch (IOException e) {
    // Handle I/O errors
    throw new RuntimeException("Failed to access path: " + data, e);
}
```

## Explanation

The original code concatenates untrusted user input directly into an operating system command string, which is then executed via `Runtime.exec()`. On Windows, this command invokes `cmd.exe /c dir`, and on Unix-like systems, it invokes `/bin/ls`. An attacker can inject shell metacharacters (`;`, `|`, `&`, etc.) into the `data` parameter to execute arbitrary commands with the privileges of the application.

The fix eliminates the Runtime.exec() call entirely by replacing it with Java's native `java.nio.file.Files` API. The `Files.newDirectoryStream()` method safely lists directory contents without spawning an external process. Input validation is applied as a secondary defense layer: the code rejects paths containing `..` (path traversal), starting with `-` (flag injection), or null/empty values. The path is normalized to its absolute form, and existence checks are performed before accessing the filesystem. This eliminates both the injection vector and the external command execution, closing CWE-78 completely.

## Behaviour changes

The fixed code replaces shell-based directory listing with Java's native file I/O API. 

**Changes:**
1. **No external process execution**: The original code spawned an OS process (`Runtime.exec()`); the fixed code uses only Java APIs, eliminating the attack surface.
2. **Input validation applied**: The fix validates the input path to reject dangerous patterns (`..`, leading `-`, null/empty), preventing both path traversal and argument injection attacks.
3. **Path normalization**: Uses `toAbsolutePath().normalize()` to resolve symbolic links and relative paths, ensuring the path is canonical.
4. **Directory vs. file handling**: The fixed code explicitly checks whether the target is a directory or file using `Files.isDirectory()` and `Files.isRegularFile()`, whereas the original command line would pass all parameters to the `dir`/`ls` command (which may handle them differently on different systems).
5. **Exception handling**: The fixed code wraps file I/O in try-catch to handle `IOException`, whereas the original code called `process.waitFor()` and would not detect command failures until process completion.
6. **No shell interpretation**: The fixed code makes no use of shell parsing, eliminating the possibility of shell metacharacter injection entirely (the original was vulnerable to commands like `; rm -rf /`, `| cat /etc/passwd`, etc.).

The original code did not capture or use the output from the `dir`/`ls` command (it only called `process.waitFor()`), so the fixed code preserves the functional behavior: confirming directory access succeeds or raising an exception on failure. The fix trades the OS command execution for native Java file I/O operations, which is strictly safer while retaining the intended functionality.

