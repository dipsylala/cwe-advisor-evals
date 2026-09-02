## Verdict
OS Command Injection - CWE-78

## Source
`data` parameter passed from `Case15A.handle()` to `Case15B.handleSink()` without sanitization (line 18 in Case15A calls line 11 in Case15B).

## Fix
Replace line 28 in Case15B.java:
```java
Process process = Runtime.getRuntime().exec(osCommand + data);
```

With:
```java
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

Or more concisely, replace line 28 with:
```java
Process process = Runtime.getRuntime().exec(new String[]{
    System.getProperty("os.name").toLowerCase().indexOf("win") >= 0 ? "c:\\WINDOWS\\SYSTEM32\\cmd.exe" : "/bin/ls",
    System.getProperty("os.name").toLowerCase().indexOf("win") >= 0 ? "/c" : null,
    System.getProperty("os.name").toLowerCase().indexOf("win") >= 0 ? "dir" : null,
    data
});
```

The simplest approach is to pass arguments as an array to `Runtime.getRuntime().exec()`, which bypasses shell interpretation.

## Explanation
The original code concatenates user input (`data`) directly into a shell command string, which is then executed by the shell interpreter. This allows an attacker to inject shell metacharacters and arbitrary commands. By passing the command and arguments as a `String[]` array instead of a single shell string, the JVM bypasses shell interpretation and treats the arguments literally, preventing command injection. The array form of `exec()` does not invoke the shell to parse the input.
