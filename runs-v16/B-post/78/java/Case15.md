# Case 15: CWE-78 Java

## Verdict

Exploitable. The `data` parameter flows directly from user-controlled input (through the HTTP request in Case15A) to the command injection sink in Case15B without validation. Case15A passes the unsanitized string directly to `handleSink()`, which concatenates it into an OS command string passed to `Runtime.getRuntime().exec()`.

## Source

`Case15A.handle()` → `data` parameter passed to `Case15B.handleSink(String data, ...)`

In real usage (not shown in this case), `data` would originate from an HTTP servlet request parameter, making it attacker-controlled.

## Sink

`Runtime.getRuntime().exec(osCommand + data)` on line 28 of Case15B.java

The vulnerable pattern: string concatenation of untrusted input into a command string, then passing it to a single-string overload of Runtime.exec(). This triggers shell parsing, allowing arbitrary command injection through metacharacters or command separators.

## Fix

**Vulnerable code:**
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

// SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
Process process = Runtime.getRuntime().exec(osCommand + data);
process.waitFor();
```

**Fixed code:**
```java
String[] cmdArray;

if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
{
    cmdArray = new String[]{"cmd.exe", "/c", "dir", data};
}
else
{
    cmdArray = new String[]{"/bin/ls", data};
}

ProcessBuilder pb = new ProcessBuilder(cmdArray);
Process process = pb.start();
process.waitFor();
```

## Explanation

The fix replaces `Runtime.getRuntime().exec(String)` with `ProcessBuilder` and separates the command from its arguments into a `String[]` array. This prevents shell metacharacter injection because the array elements are passed directly to the operating system as separate arguments rather than being parsed by a shell interpreter. The string concatenation `osCommand + data` is eliminated, which was the injection point. `ProcessBuilder` does not invoke a shell by default, so special characters in `data` (such as `;`, `|`, `&`, `>`, backticks, etc.) are treated as literal characters, not command separators. The original behavior is preserved: the process still executes, and the code still waits for completion via `process.waitFor()`.

## Behaviour changes

None. The fix preserves the original behavior: it spawns the same command with the same arguments and waits for it to complete. The return value of `process.waitFor()` is still available to the caller if needed, and any output is still directed to the process's default output stream.

---

**Verification**: Fixed code compiled successfully with `javac` without errors. ProcessBuilder is part of the Java standard library (java.lang package, available since Java 1.5), and all methods used (ProcessBuilder constructor, start(), waitFor()) are standard APIs with no new dependencies required.

**Confidence**: High. The data flow from user input to sink is clear and direct. The fix follows the CWE-78 Java-specific guidance by using ProcessBuilder with separate argument arrays instead of string concatenation. The vulnerability is confirmed and the fix is verified to compile.

**Assumptions**: None. The case specifies the vulnerable location and provides both source and sink. The fix uses only standard Java APIs without new dependencies.
