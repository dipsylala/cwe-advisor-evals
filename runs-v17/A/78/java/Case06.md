## Verdict
CONFIRMED - OS Command Injection via unsafe Runtime.exec() string concatenation

## Source
Untrusted data flows from HTTP request parameter → Case06A.handle() → through call chain B→C→D→E → Case06E.handleSink() at line 28

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

        String[] cmd;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            
            cmd = new String[]{"c:\\WINDOWS\\SYSTEM32\\cmd.exe", "/c", "dir", data};
        }
        else
        {
            
            cmd = new String[]{"/bin/ls", data};
        }

        
        // SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
        Process process = Runtime.getRuntime().exec(cmd);
        process.waitFor();

    }
}
```

## Explanation
The vulnerability exists at line 28 where untrusted user input (`data`) is concatenated directly into a command string passed to `Runtime.getRuntime().exec(String)`. This allows an attacker to inject shell metacharacters or additional commands.

The fix uses the `exec(String[])` overload instead, which accepts an array of separate command arguments. Each element in the array is passed as a distinct argument to the target program without shell interpretation. This prevents the shell from treating special characters in the `data` parameter as command separators or metacharacters.

The Windows command becomes a 4-element array: the executable path, the `/c` flag, the `dir` subcommand, and the user data as a literal filename argument. The Unix command becomes a 2-element array: the `ls` executable and the user data as a literal filename argument. In both cases, shell metacharacters in `data` are neutralized because they are never passed through a command shell; they are passed directly to the target program as literal filename strings.
