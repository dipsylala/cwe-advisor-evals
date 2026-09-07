## Verdict
CONFIRMED - OS command injection vulnerability via unsanitized user input

## Source
HTTP request parameter `name` flows from `Case05A.handle()` → `Case05B.handleSink()` → `Case05C.handleSink()` → `Case05D.handleSink()` where it is concatenated into an OS command string and executed without validation.

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
            
            cmd = new String[]{"c:\\WINDOWS\\SYSTEM32\\cmd.exe", "/c", "dir", data};
        }
        else
        {
            
            cmd = new String[]{"/bin/ls", data};
        }

        
        // Fixed: Use array form of Runtime.exec() to prevent shell metacharacter interpretation
        Process process = Runtime.getRuntime().exec(cmd);
        process.waitFor();

    }
}
```

## Explanation
The original code concatenated the untrusted `data` parameter directly into an OS command string: `Runtime.getRuntime().exec(osCommand + data)`. This allows an attacker to inject shell metacharacters (`;`, `|`, `&`, `$()`, backticks, etc.) to execute arbitrary commands.

The fix uses the array-based form of `Runtime.getRuntime().exec(String[] cmdarray)`, which passes arguments as separate array elements. This prevents the shell from interpreting special characters in the array elements as metacharacters — each element is passed directly to the command as an argument without further parsing.

The command and its arguments are now cleanly separated: the base command (`cmd.exe /c dir` or `/bin/ls`) remains fixed, and the user-supplied parameter is passed only as a final argument. An input like `dir; rm -rf /` will be treated as a directory name to list, not as shell commands to execute.
