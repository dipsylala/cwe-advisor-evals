## Verdict

CWE-78 (OS Command Injection) confirmed. User-controlled input from `request.getParameter()` in Case04A is concatenated directly into an OS command string and executed via `Runtime.getRuntime().exec()` in Case04B, line 28.

## Source

The data flow originates in Case04A.java:
- Line 16: `data = request.getParameter("name")` retrieves untrusted user input
- Line 18: passed to `Case04B.handleSink(data, ...)`

The sink is Case04B.java, line 28:
- `Process process = Runtime.getRuntime().exec(osCommand + data);`

The command string is built via concatenation: `osCommand + data` where `osCommand` is either `"c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir "` or `"/bin/ls "`, then passed as a single string to `exec()`. This variant of `exec()` invokes a shell to parse the command string, allowing an attacker to inject shell metacharacters (`;`, `|`, `&`, `&&`, `||`, etc.) to execute arbitrary commands.

## Fix

Use the `exec()` variant that accepts a `String[]` argument array. This passes the command and arguments directly to the OS without shell interpretation:

```java
String[] command;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
{
    command = new String[]{"cmd.exe", "/c", "dir", data};
}
else
{
    command = new String[]{"/bin/ls", data};
}

Process process = Runtime.getRuntime().exec(command);
```

Alternatively, constrain `data` to a known-safe format (e.g., alphanumeric and hyphens only) if the use case permits, then validate it with a pattern match before use.

## Explanation

The single-string variant of `Runtime.getRuntime().exec(String)` invokes the shell, which parses metacharacters. The argument-array variant `exec(String[])` passes each element separately to the OS without shell interpretation, preventing an attacker from injecting shell operators into user-supplied arguments.

The fix splits the command and arguments into an array: the executable is the first element, and each argument (including user input) becomes a separate array element. The OS then invokes the executable with those literal argument values, with no shell parsing of `data`.
