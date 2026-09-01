## Verdict

OS Command Injection vulnerability confirmed at line 28 of Case15B.java. The user-controlled `data` parameter is concatenated directly into a shell command string and executed via `Runtime.getRuntime().exec()`, allowing arbitrary command injection.

## Source

In Case15B.java, the `handleSink()` method receives user input via the `data` parameter (traced from Case15A where it originates from request data). At line 28, this data is concatenated directly into a command string:

```
osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir " + data;  // or "/bin/ls " + data
Process process = Runtime.getRuntime().exec(osCommand + data);
```

The `Runtime.exec(String)` method splits the input on whitespace, allowing shell metacharacters in `data` to be interpreted as command separators or operators.

## Fix

Replace the string concatenation approach with the array form of `Runtime.exec()`, which passes each element as a separate argument without shell interpretation:

```java
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
```

Additionally, validate that `data` does not start with a dash (option introducer) to prevent flag injection attacks that can modify command behavior even when using the array form:

```java
if (data.startsWith("-")) {
    throw new IllegalArgumentException("Invalid input: path must not start with dash");
}
```

## Explanation

The vulnerability arises from using `Runtime.exec(String)`, which internally splits the command on whitespace but does not prevent shell metacharacter interpretation when the string is constructed with user input. An attacker can inject commands by including shell operators such as `; rm -rf /` or `| cat /etc/passwd`.

The fix uses `Runtime.exec(String[])`, which treats each array element as a discrete argument passed directly to the target process. This prevents the shell from interpreting metacharacters in `data` as command separators.

However, even with the array form, leading dashes in `data` can be misinterpreted as options by `dir` or `ls`, potentially altering behavior. Rejecting inputs that start with `-` prevents this secondary injection vector. This check should be applied before the command is constructed.
