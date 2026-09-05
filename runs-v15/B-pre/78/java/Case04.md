## Verdict

Exploitable

## Source

`request.getParameter("name")` in Case04A.java line 16. This HTTP request parameter is untrusted user input with no validation.

## Fix

**Vulnerable code** (Case04B.java lines 14–29):
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

// Sink: user input concatenated directly into command string
Process process = Runtime.getRuntime().exec(osCommand + data);
process.waitFor();
```

**Fixed code**:
```java
// Validate input to prevent path traversal and injection
if (data == null || data.isEmpty() || data.contains("..") || 
    data.contains("|") || data.contains(";") || data.contains("&") || 
    data.contains("$") || data.contains("`") || data.contains("(") || 
    data.contains(")")) {
    throw new IllegalArgumentException("Invalid directory path: special characters or path traversal not allowed");
}

// Use Java's native file API instead of shell execution
Path targetPath = Paths.get(data);
try (Stream<Path> paths = Files.list(targetPath)) {
    paths.map(Path::toString)
         .forEach(System.out::println);
} catch (IOException e) {
    throw new RuntimeException("Unable to list directory: " + e.getMessage(), e);
}
```

Add imports (if not present):
```java
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;
```

## Explanation

The vulnerability allows arbitrary OS command injection: an attacker passes malicious input like `; cat /etc/passwd` or `$(whoami)`, which gets concatenated into the command string and executed via the shell. The primary remediation is to eliminate `Runtime.exec()` entirely and replace it with a Java native library. The original code's purpose is to list directory contents, which `Files.list()` does natively without invoking a shell. The fixed code validates the input to reject path traversal sequences (`..`), shell metacharacters (`;`, `|`, `&`, `$`, backticks, parentheses), and null/empty values before using it. Because `Files.list()` does not invoke a shell, it is immune to command injection: the path is interpreted as a literal filesystem path, never parsed by a command interpreter. The original code printed directory contents to stdout via the `dir` or `ls` command; the fixed code achieves the same output using `Stream<Path>` and `System.out.println()`.

## Behaviour changes

- Eliminated cross-platform shell branching. The original code conditionally invoked `cmd.exe` on Windows or `/bin/ls` on Unix; the fixed code uses a platform-agnostic Java API that lists directories on any OS.
- Input validation added. The original code accepted any string; the fixed code rejects strings containing path traversal sequences and shell metacharacters. This is necessary for safety and changes the contract: invalid inputs now throw `IllegalArgumentException` instead of being passed to the shell.
- Exception handling changed. The original `Runtime.exec()` and `waitFor()` calls are replaced with `Files.list()` wrapped in a try-catch that throws `RuntimeException` on `IOException`. This preserves failure semantics (an exception is thrown when the directory cannot be listed) but changes the exception type.
- Return value. The original method returned `void` and the Process object was discarded without reading its output or exit code. The fixed code preserves the void return and prints results to stdout, matching the visible behaviour of the original `dir`/`ls` commands.
