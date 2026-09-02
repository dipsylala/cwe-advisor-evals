## Verdict

Real OS command injection vulnerability. User-controlled input from `request.getParameter("name")` flows through the call chain (Case05A → Case05B → Case05C) to Case05D line 28, where it is concatenated directly into a command string passed to `Runtime.getRuntime().exec()`. An attacker can inject shell metacharacters or additional commands.

## Source

The `data` parameter originating from `request.getParameter("name")` in Case05A (line 16) is untrusted and attacker-controlled.

## Fix

Replace the string concatenation approach with `ProcessBuilder` and pass the command and arguments as separate array elements to prevent shell interpretation of the data parameter:

```java
ProcessBuilder pb;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
    pb = new ProcessBuilder("c:\\WINDOWS\\SYSTEM32\\cmd.exe", "/c", "dir", data);
} else {
    pb = new ProcessBuilder("/bin/ls", data);
}
Process process = pb.start();
process.waitFor();
```

## Explanation

The vulnerability occurs because `Runtime.getRuntime().exec(osCommand + data)` concatenates untrusted input directly into the command string. Although `exec()` with a single string argument does not invoke a shell (unlike `Runtime.exec(String[])` with space-split parsing), the correct fix is to use `ProcessBuilder` with separate arguments.

`ProcessBuilder` accepts a list of command and arguments, where each element is treated as a literal argument rather than subject to further parsing. By passing `data` as a distinct argument (not concatenated into the command string), metacharacters and command separators within `data` are passed safely to the target program (`cmd.exe`, `ls`, etc.) as literal argument values rather than interpreted as commands.

This approach also correctly preserves the platform-specific command structure: Windows needs `cmd.exe /c` to execute the `dir` command with user input, while Linux runs `ls` directly with the argument.
