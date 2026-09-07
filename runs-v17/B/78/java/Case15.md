## Verdict

Exploitable. User-supplied `data` parameter is concatenated directly into an OS command string and executed via `Runtime.getRuntime().exec()` without validation or parameterization.

## Source

HTTP request parameter passed from Case15A to Case15B.handleSink() as the `data` parameter. In Case15A, the parameter flows from an HTTP servlet request to the sink in Case15B at line 28.

## Fix

### File: Case15B.java

```java
package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;
import java.nio.file.*;
import java.util.stream.Stream;

public class Case15B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        // Use Files API instead of system command execution to prevent OS command injection
        try (Stream<Path> paths = Files.list(Paths.get(data))) {
            paths.forEach(System.out::println);
        }
    }
}
```

## Explanation

The vulnerability is eliminated by replacing OS command execution with Java's native `java.nio.file.Files` API. The original code attempted to list directory contents using shell commands (`cmd.exe /c dir` on Windows or `/bin/ls` on Unix), but by using `Files.list()` directly, the code achieves the same result without spawning a shell or interpreting user input as command syntax. The data parameter is now treated purely as a filesystem path and not concatenated into a command string. The try-with-resources block ensures proper resource cleanup of the directory stream.

## Behaviour changes

- Original code: Spawned a separate process via `Runtime.exec()`, causing the command's output to appear in the spawned process's stdout stream, and called `Process.waitFor()` to wait for completion.
- Fixed code: Lists directory contents directly using Java's Files API, outputting results to the application's `System.out`. The operation completes synchronously without spawning a separate process.
- The fix preserves the core functionality (listing directory contents) while eliminating the command injection vector. Error handling is implicitly provided by exception propagation, matching the original code's behavior of letting exceptions bubble up.
