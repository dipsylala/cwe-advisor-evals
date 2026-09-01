## Verdict
OS Command Injection confirmed. Untrusted user input from `request.getParameter("name")` is concatenated directly into a shell command string passed to `Runtime.getRuntime().exec()` at line 28 of Case04B.java.

## Source
Line 16 in Case04A.java: `data = request.getParameter("name")` — receives untrusted user input
Line 18 in Case04A.java: passes `data` to `Case04B.handleSink()`
Line 28 in Case04B.java: `Process process = Runtime.getRuntime().exec(osCommand + data)` — sinks data into a shell command

## Fix
Replace line 28 in Case04B.java with a `ProcessBuilder` that passes the user data as a separate argument array element, avoiding shell tokenization:

```java
ProcessBuilder pb;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
{
    pb = new ProcessBuilder("c:\\WINDOWS\\SYSTEM32\\cmd.exe", "/c", "dir", data);
}
else
{
    pb = new ProcessBuilder("/bin/ls", data);
}
Process process = pb.start();
process.waitFor();
```

## Explanation
`Runtime.exec(String)` parses the input string through the OS shell, allowing shell metacharacters in `data` (such as `; malicious_command` or `| malicious_command`) to escape the intended command and execute arbitrary code. `ProcessBuilder` with an array of command and arguments treats each array element as a literal token, preventing shell interpretation. The user-supplied `data` is now passed as a distinct operand rather than concatenated into the command string, eliminating the injection vector.
