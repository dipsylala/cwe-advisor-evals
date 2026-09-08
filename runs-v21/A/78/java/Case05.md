## Verdict
CONFIRMED - OS Command Injection vulnerability exists at line 28 of Case05D.java where user-controlled data is concatenated directly into an OS command string.

## Source
User input flows from `request.getParameter("name")` in Case05A through the chain of handlers (Case05B → Case05C → Case05D) to the OS command sink in Case05D.

## Fix
### File: Case05D.java
```java
package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case05D
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String[] cmd;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            cmd = new String[]{"cmd.exe", "/c", "dir", data};
        }
        else
        {
            cmd = new String[]{"/bin/ls", data};
        }

        Process process = Runtime.getRuntime().exec(cmd);
        process.waitFor();
    }
}
```

## Explanation
The vulnerability occurs because user-supplied data is concatenated into an OS command string and passed to `Runtime.getRuntime().exec(String)`, which interprets shell metacharacters. An attacker can inject shell operators (e.g., `; rm -rf /` or `& del *.*`) through the `name` parameter to execute arbitrary commands.

The fix uses `Runtime.getRuntime().exec(String[])` with an array of arguments instead of string concatenation. This prevents the JVM from parsing shell metacharacters and passes arguments directly to the target program without shell interpretation. User input is now passed as a separate argument to the dir/ls command rather than concatenated into the command string, eliminating the injection vector.
