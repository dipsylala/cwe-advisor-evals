## Verdict

Exploitable

## Source

Case05A.java, line 16: `data = request.getParameter("name")` - untrusted HTTP request parameter flows through Case05B and Case05C unchanged to the sink.

## Fix

**Vulnerable code (Case05D.java, lines 14-29):**

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
Process process = Runtime.getRuntime().exec(osCommand + data);  // VULNERABLE
process.waitFor();
```

**Fixed code (Case05D.java, lines 14-33):**

```java
import java.nio.file.*;
import java.io.IOException;

// Replace Runtime.exec() with Java native File I/O APIs
try {
    // List files in the directory specified by data
    Files.list(Paths.get(data))
        .forEach(p -> System.out.println(p.getFileName()));
} catch (IOException e) {
    System.err.println("Error listing directory: " + e.getMessage());
}
```

## Explanation

The vulnerability eliminates OS command execution entirely by replacing it with Java's native `java.nio.file.Files.list()` API. This approach satisfies the guidance principle: the purpose of the code is to list a directory—a file operation—not to execute commands. The command execution itself is incidental and unsafe. Using Java APIs removes the injection sink completely, making it impossible to inject arbitrary commands regardless of the input value. The try-catch block handles IOException that may occur if the path is invalid or not a directory, maintaining error handling behavior. The `forEach` and `System.out.println()` preserve the original behavior of printing directory contents to stdout without requiring a separate process.

## Behaviour changes

The fix changes the output format compared to the original `dir` and `ls` commands. Where the original commands would output formatted directory listings with metadata (file size, modification time, etc.), the fixed code prints only filenames, one per line. This is acceptable because:

1. The primary objective—listing directory contents—is preserved
2. The guidance prioritizes eliminating command execution over preserving exact output formatting
3. The vulnerability (OS command injection) is completely closed
4. If the original formatting is required, the caller can capture the results and format them programmatically rather than relying on an external command

No other behavior changes occur: error handling is preserved through IOException catching, and the method remains void.
