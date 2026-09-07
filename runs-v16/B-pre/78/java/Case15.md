## Verdict
Exploitable. The `data` parameter is concatenated directly into an OS command string without validation or escaping, allowing command injection via shell operators.

## Source
`data` parameter passed to `Case15B.handleSink()` from `Case15A.handle()`. Currently hardcoded to `"foo"` in the test case, but the method signature permits attacker-controlled input through the HTTP request chain.

## Sink
`Runtime.getRuntime().exec(osCommand + data)` at line 28 of `Case15B.java`, where `osCommand` is constructed as an absolute path (`/bin/ls` or `c:\WINDOWS\SYSTEM32\cmd.exe /c dir`) and `data` is appended via string concatenation.

## Attack Path
An attacker providing `data = "; rm -rf /"` results in the command `/bin/ls ; rm -rf /`, which executes both the listing command and the injected command due to shell metacharacter interpretation. The absolute path to the shell command does not prevent injection when the value is concatenated into a command string.

## Fix

**Vulnerable Code:**
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

**Fixed Code:**
```java
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;
import java.io.IOException;

// ... in handleSink method:

try {
    Path path = Paths.get(data);
    if (Files.exists(path)) {
        if (Files.isDirectory(path)) {
            try (Stream<Path> stream = Files.list(path)) {
                stream.map(Path::getFileName).forEach(System.out::println);
            }
        } else {
            System.out.println(path.getFileName());
        }
    }
} catch (IOException e) {
    e.printStackTrace();
}
```

## Explanation
The fix eliminates OS command execution entirely by replacing the shell command with Java's native file system APIs (`Files.list()`, `Files.isDirectory()`, `Paths.get()`). This removes the injection point: no user input is ever concatenated into a command string. The `data` parameter is treated as a file path argument to the Java API, not as part of a command line. The `Paths.get()` call interprets `data` as a filesystem path name without shell interpretation, and `Files.list()` retrieves directory contents without spawning a process. The original code's behavior—listing files and printing them to stdout—is preserved through Java's stream processing.

## Behaviour changes
- **Removed process spawning**: Original code created a Process object and called `waitFor()`. Fixed code uses only Java APIs; no external process is created. This removes the indirect dependency on the shell's behavior.
- **Output handling preserved**: Original code's output went to stdout through the spawned process. Fixed code uses `System.out.println()` to print file names directly, preserving the visible behavior.
- **Error handling changed**: Original code would silently succeed or fail depending on whether the command executable existed and could execute. Fixed code explicitly catches `IOException` to handle file access errors; this provides better diagnostics if the path is invalid or inaccessible.
- **No shell environment inheritance**: The original ProcessBuilder/Runtime.exec approach inherited the shell environment (PATH, env vars, etc.). The fixed code does not execute any external command, eliminating that side channel.
- **Symlink handling**: `Files.list()` follows symlinks by default; the original `ls` or `dir` command behavior varies by platform and options. If the application requires specific symlink handling, additional flags on `Files.list()` (e.g., `FileVisitOption.FOLLOW_LINKS`) or use of `Files.walk()` may be needed.
