## Verdict

CWE-78 (OS Command Injection) confirmed. User input from HTTP request parameter flows directly into `Runtime.getRuntime().exec(String)` concatenated with a command string, allowing shell metacharacter injection.

## Source

Case04A.java line 16: `data = request.getParameter("name")` receives untrusted user input from HTTP request parameter.

The tainted data flows to Case04B.handleSink() at line 18, then concatenated into the command string at line 28.

## Fix

### File: Case04B.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case04B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        Process process;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            
            process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", "dir", data});
        }
        else
        {
            
            process = Runtime.getRuntime().exec(new String[]{"ls", "--", data});
        }

        
        process.waitFor();

    }
}
```

## Explanation

The vulnerability occurs because `Runtime.getRuntime().exec(String command)` invokes a shell to parse and execute the command. When user input is concatenated into the command string, shell metacharacters (`&`, `|`, `;`, `$()`, `` ` ``) are interpreted by the shell, allowing arbitrary command execution.

The fix uses the array form of `exec()`: `Runtime.getRuntime().exec(String[] cmdarray)`. This passes each command component as a separate argument directly to the process, bypassing shell parsing entirely. The array form does not invoke a shell parser, so metacharacters in the data argument are treated as literal characters, not shell operators.

Additionally:
- On Unix/Linux, the `--` marker tells `ls` that everything following is an operand (not an option), preventing data that starts with `-` from being interpreted as a flag.
- On Windows, `cmd.exe /c` followed by separate arguments in an array prevents the directory name from being reinterpreted through shell parsing.

This approach eliminates the injection vector while maintaining the intended functionality.
