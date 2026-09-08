## Verdict
VULNERABLE

The code at line 28 of Case04B.java performs OS command injection by concatenating untrusted user input from an HTTP request parameter directly into a shell command string passed to `Runtime.getRuntime().exec()`.

## Source
Case04A.java line 16 receives untrusted input via `request.getParameter("name")` and passes it to Case04B.handleSink() without validation.

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

        String[] cmdArray;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            
            cmdArray = new String[]{"c:\\WINDOWS\\SYSTEM32\\cmd.exe", "/c", "dir", data};
        }
        else
        {
            
            cmdArray = new String[]{"/bin/ls", data};
        }

        
        // Use Runtime.exec(String[]) to avoid shell interpretation
        Process process = Runtime.getRuntime().exec(cmdArray);
        process.waitFor();

    }
}
```

## Explanation
The vulnerability is remediated by replacing the string concatenation approach with `Runtime.exec(String[])`, which accepts an array of arguments. Each array element is passed directly to the executed program without shell interpretation, preventing injection of command separators, pipes, redirects, and other shell metacharacters. The command components (program, flags, and user-supplied arguments) are now properly separated into distinct array elements, ensuring `data` is treated as a literal argument value to `ls` or `dir` rather than as arbitrary shell code.
