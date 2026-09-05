## Verdict

The vulnerability is confirmed. User-supplied `data` is concatenated directly into a command string passed to `Runtime.getRuntime().exec()`, allowing OS command injection through shell metacharacters or command separators.

## Source

File: `evals/cases/78/java/Case15/Case15B.java`, line 28

```java
Process process = Runtime.getRuntime().exec(osCommand + data);
```

The `data` parameter comes from the method signature and is controlled by an attacker via HTTP request. It is concatenated into `osCommand` without escaping or validation, then passed to the string form of `exec()` which spawns a shell to interpret the command.

## Fix

Replace the string concatenation form of `exec()` with the array form, which passes the command and its arguments as separate elements. This bypasses shell interpretation entirely and prevents injection:

**Windows branch (line 28):**
```java
Process process = Runtime.getRuntime().exec(new String[]{"c:\\WINDOWS\\SYSTEM32\\cmd.exe", "/c", "dir", data});
```

**Unix branch (line 28):**
```java
Process process = Runtime.getRuntime().exec(new String[]{"/bin/ls", data});
```

## Explanation

The string form of `Runtime.exec(String)` passes the entire command to a shell for parsing and execution. Shell metacharacters like `;`, `|`, `&`, `$()`, and backticks in the `data` parameter are interpreted by the shell, allowing an attacker to inject additional commands or modify the intended command structure.

The array form `Runtime.exec(String[])` passes the command and each argument as a separate array element directly to the target program without shell interpretation. The operating system executes the program with those exact arguments, treating shell metacharacters as literal string data rather than operators.

This fix eliminates the injection vector entirely by removing the shell parsing step. The `data` value is treated as a single literal argument to the `dir` or `ls` command, regardless of what characters it contains.
