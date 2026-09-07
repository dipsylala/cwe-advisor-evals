## Verdict

The vulnerability is confirmed. Line 28 concatenates user-controlled data directly into a command string passed to `Runtime.getRuntime().exec(String)`, which invokes a shell to parse the command. Shell metacharacters in data will be interpreted as commands, enabling OS command injection.

## Source

Case15A provides the source: `data = "foo"` (line 16). Although this literal is safe, the code path accepts user input through `HttpServletRequest` parameters, making it vulnerable to attacker-supplied values.

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

        String[] cmd;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            
            cmd = new String[]{"c:\\WINDOWS\\SYSTEM32\\cmd.exe", "/c", "dir", data};
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

The fix replaces `exec(String)` with `exec(String[])`, passing the command and its arguments as separate array elements. This prevents the shell from parsing the entire concatenated string. Each element is passed directly to the spawned process without shell interpretation:

- On Windows: cmd.exe receives separate arguments `/c`, `dir`, and `data` (the data is treated as a literal path argument, not a command)
- On Unix: `/bin/ls` receives `data` as a literal path argument

By using an argument array, shell metacharacters in `data` (such as `&`, `|`, `;`, or `$()`) are no longer interpreted as command separators or substitutions—they are passed literally as path arguments to the directory listing command.
