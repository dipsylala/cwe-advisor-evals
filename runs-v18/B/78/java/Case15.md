## Verdict

exploitable

## Source

The `data` parameter of the `handleSink()` method (untrusted, attacker-controlled input from the HTTP request).

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
        // Validate input to prevent argument injection (CWE-88)
        if (data != null && data.startsWith("-")) {
            throw new IllegalArgumentException("Argument cannot start with '-'");
        }

        ProcessBuilder pb;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            pb = new ProcessBuilder("c:\\WINDOWS\\SYSTEM32\\cmd.exe", "/c", "dir", data != null ? data : "");
        }
        else
        {
            pb = new ProcessBuilder("/bin/ls", data != null ? data : "");
        }

        Process process = pb.start();
        process.waitFor();
    }
}
```

## Explanation

The original code concatenated untrusted user input (`data`) directly into a command string passed to `Runtime.getRuntime().exec()`, enabling OS command injection. The fix replaces this with `ProcessBuilder` using a separate argument array. By passing arguments as individual elements in the array rather than concatenating them into a single string, the fix prevents shell metacharacter injection. Additionally, input validation rejects arguments starting with `-` to prevent argument injection attacks (CWE-88) where an attacker could inject unintended flags or options into the target program. The ProcessBuilder approach is the parameterized execution API recommended for Java when command execution is unavoidable.

## Behaviour changes

The original code used `Runtime.getRuntime().exec(String)` which tokenizes the input string internally using `StringTokenizer`. The fixed code uses `ProcessBuilder` with an explicit argument array. This changes the argument parsing behavior: the original `Runtime.exec(String)` would tokenize "dir /s /b" into three separate arguments; ProcessBuilder passes arguments individually as supplied, which is more predictable and safer. The return value (`Process` object) and failure behavior (throws IOException on spawn failure) remain identical. Both versions leave stdout/stderr uncaptured, so no output is discarded. The validation gate adds a behavioral requirement: data starting with `-` now raises `IllegalArgumentException`, whereas the original would have passed it through; this is a security-necessary constraint. On Windows, the original string concatenation would allow commands like `cmd.exe /c dir & whoami` to execute multiple commands; ProcessBuilder with separate arguments passes this as a literal directory name instead, preventing the attack.
