## Verdict
OS Command Injection via string concatenation into Runtime.exec(). User input must be passed as a separate argument, not concatenated into the command string.

## Source
Case06A receives untrusted parameter from `request.getParameter("name")` and passes it through the call chain (B → C → D → E) to Case06E line 28, where it is concatenated into an OS command string.

## Fix

### File: Case06E.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case06E
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
            
            process = Runtime.getRuntime().exec(new String[]{"/bin/ls", data});
        }

        
        process.waitFor();

    }
}
```

## Explanation
The vulnerability at line 28 concatenates untrusted user input directly into an OS command string: `Runtime.getRuntime().exec(osCommand + data)`. When `exec()` receives a single string argument, it spawns a shell that interprets the entire string, allowing an attacker to inject shell metacharacters (`;`, `|`, `&`, etc.) to execute arbitrary commands.

The fix uses the array form of `exec(String[])`, which passes the base command and arguments as separate elements. The Java runtime passes these directly to the process without shell interpretation. The user-supplied `data` is now treated as a literal argument value, not part of the command syntax itself. Shell metacharacters in the argument have no special meaning and cannot break out of the intended command.

For both Windows and Linux cases, the data is passed as the final array element, ensuring it is safely handled as an argument to `dir` or `ls` respectively.
