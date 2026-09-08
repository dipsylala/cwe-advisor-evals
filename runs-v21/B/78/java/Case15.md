## Verdict

Exploitable. The data parameter is concatenated directly into an OS command string without using an argument array, enabling OS command injection. The vulnerable pattern `Runtime.getRuntime().exec(osCommand + data)` allows an attacker to inject arbitrary shell commands via the data parameter.

## Source

Data source: String `data` parameter to `Case15B.handleSink()` method (line 11 of Case15B.java). In Case15A, this data originates from a hardcoded value ("foo"), but the vulnerability exists in the general pattern where this could receive attacker-controlled input.

## Fix

### File: Case15B.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

public class Case15B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        // Use Java's Files API instead of OS command execution
        // This eliminates the command injection vulnerability entirely
        Path dirPath = Paths.get(data);

        try (Stream<Path> stream = Files.list(dirPath)) {
            stream.forEach(path -> System.out.println(path.getFileName()));
        }

    }
}
```

## Explanation

The original code executed OS commands (`cmd.exe /c dir` on Windows or `/bin/ls` on Unix) by concatenating untrusted data directly into a command string passed to `Runtime.getRuntime().exec()`. This enabled an attacker to inject arbitrary shell metacharacters or commands through the data parameter.

The fix replaces the OS command execution entirely with Java's native `Files` API (`java.nio.file.Files.list()`), which lists directory contents without invoking any shell or external process. This eliminates the injection surface completely. The `Paths.get(data)` converts the user-provided string to a `Path` object, and `Files.list()` safely enumerates files in that directory. The stream is properly managed using try-with-resources to ensure it is closed. The output is printed to stdout, preserving the original behavior of displaying file listings. All required APIs (`Files.list()`, `Path`, `Paths.get()`, `Stream`) are from the Java standard library (java.nio.file and java.util.stream) available since Java 7 (Stream since Java 8).

## Behaviour changes

**Output format change:** The original code used OS command output (Windows `dir` or Unix `ls` format), while the fixed code prints only file names (via `path.getFileName()`), one per line. This is a simplification and does not introduce a security regression, but consumers relying on the exact format of the original command output would see a different output.

**Exception handling change:** The original code would throw IOException only from Runtime.exec() or Process.waitFor(); the fixed code throws IOException from Files.list() if the directory does not exist or is not readable. The exception type is the same (IOException), but the context differs slightly. This maintains the same exception contract (throws Throwable).

**No return value change:** The original code discarded the exit code from Process.waitFor(); the fixed code also discards the stream's result, so the return contract is preserved (method returns void).
