## Verdict

CONFIRMED - CWE-78 (OS Command Injection) vulnerability exists at line 28. User-supplied data is concatenated into a command string and passed to `Runtime.getRuntime().exec(String)`, which uses shell parsing that interprets metacharacters in the data.

## Source

`data` parameter in `Case15B.handleSink()` method, originating from `Case15A.handle()`.

## Fix

### File: Case15B.java

```java
package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case15B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        ProcessBuilder pb;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            pb = new ProcessBuilder("cmd.exe", "/c", "dir", data);
        }
        else
        {
            pb = new ProcessBuilder("/bin/ls", "--", data);
        }

        Process process = pb.start();
        process.waitFor();

    }
}
```

## Explanation

The vulnerable code concatenated `data` directly into the command string before passing it to `Runtime.getRuntime().exec(String)`, which uses shell parsing. Shell metacharacters in `data` (e.g., `; rm -rf /` or `| cat /etc/passwd`) would be interpreted by the shell, enabling arbitrary command execution.

The fix replaces `Runtime.exec(String)` with `ProcessBuilder`, passing arguments as separate list elements instead of concatenating them into a single string. This prevents the shell from interpreting metacharacters within the data:

- **Before**: `Runtime.getRuntime().exec("cmd.exe /c dir " + data)` — shell tokenizes and interprets the entire concatenated string
- **After**: `ProcessBuilder(["cmd.exe", "/c", "dir", data])` — each argument is separate; shell metacharacters in `data` are not interpreted

On Unix systems, the `--` argument after `ls` signals end-of-options, providing defense-in-depth against argument injection (CWE-88) by preventing values starting with `-` from being interpreted as flags.

## Behaviour changes

The ProcessBuilder API passes arguments correctly to the target program without shell re-parsing. This prevents shell command injection. The code still invokes the same commands (`cmd.exe /c dir` on Windows, `/bin/ls` on Unix) and produces the same output as before. Process return codes and I/O streams are handled identically (`waitFor()` still blocks until completion; stderr/stdout still discarded as in original).

The sole behavior change is security-hardening: shell metacharacters in `data` are no longer interpreted as command syntax.
