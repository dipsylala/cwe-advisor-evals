## Verdict
OS Command Injection via unquoted string concatenation into shell command. The vulnerable code passes attacker-controlled input as part of a command string to `Runtime.getRuntime().exec()`, allowing injection of shell metacharacters and arbitrary commands.

## Source
```java
String osCommand;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
{
    osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
}
else
{
    osCommand = "/bin/ls ";
}

Process process = Runtime.getRuntime().exec(osCommand + data);
```

The `data` parameter originates from the HTTP request and is concatenated directly into `osCommand`. When the string is passed to `exec()`, shell metacharacters in `data` (such as `;`, `|`, `&&`, or backticks) are interpreted as shell operators rather than literal arguments.

## Fix
```java
String osCommand;
String[] cmdArray;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
{
    cmdArray = new String[]{"c:\\WINDOWS\\SYSTEM32\\cmd.exe", "/c", "dir", data};
}
else
{
    cmdArray = new String[]{"/bin/ls", data};
}

Process process = Runtime.getRuntime().exec(cmdArray);
```

Use the array-based overload of `exec()` instead of concatenating strings. Each element of the array is a separate argument to the command; the shell does not parse metacharacters within array elements. The command name and flags are specified as separate array elements before the user-supplied data.

## Explanation
The vulnerability exists because `Runtime.getRuntime().exec(String)` passes the string to a shell for interpretation (on Unix/Linux, via `/bin/sh -c`). Concatenating untrusted data into the command string allows the attacker to inject shell metacharacters that alter the command's behavior.

The fix uses `Runtime.getRuntime().exec(String[])`, which bypasses the shell and passes arguments directly to the target process. Each array element is a discrete argument; special characters like `;`, `|`, and `$()` are treated as literal argument text, not shell operators.

This eliminates the injection vector by preventing shell metacharacter interpretation while preserving the ability to pass the directory or file argument to `ls` or `dir`.
