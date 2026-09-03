## Verdict
exploitable

## Source
Case15A.java line 18: hardcoded string "foo" passed to Case15B.handleSink()

## Fix

**Vulnerable code:**
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

**Fixed code:**
```java
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

// Replace Process execution with java.nio.file.Files API
Path targetPath = Paths.get(data);
try (DirectoryStream<Path> stream = Files.newDirectoryStream(targetPath)) {
    for (Path entry : stream) {
        // Process each directory entry
        // Replace what the original process output would have been used for
        System.out.println(entry.getFileName());
    }
} catch (NoSuchFileException | NotDirectoryException e) {
    // Handle file not found or path not a directory
    System.err.println("Directory not found: " + data);
} catch (IOException e) {
    System.err.println("Error reading directory: " + e.getMessage());
}
```

## Explanation
The original code concatenates an untrusted `data` parameter into an OS command string, then executes it via `Runtime.exec()`. This allows command injection: an attacker can inject shell metacharacters or additional commands (e.g., `foo; rm -rf /`), which the shell will interpret as separate commands. The fixed code replaces the shell-based `dir`/`ls` command with Java's native `java.nio.file.Files` and `DirectoryStream` API, which directly performs directory listing without shell parsing. This eliminates the injection vector entirely by removing the shell invocation. The `data` parameter is now used safely as a filesystem path argument, not concatenated into a command string.

## Behaviour changes
The original code returned a Process object and called `waitFor()` without capturing output. The fixed code iterates over directory entries directly using the Files API. To preserve caller expectations about output: if the original code's process output was captured downstream (not shown in this excerpt), you would need to redirect it to the caller. The fixed code shown prints to stdout for illustration; adapt the output handling to match the original code's intent. The exception handling differs: `ProcessBuilder` throws `IOException` on execution failure, while the Files API throws `NoSuchFileException` or `NotDirectoryException` for invalid paths. Error cases should be handled according to the application's logging and recovery strategy.
