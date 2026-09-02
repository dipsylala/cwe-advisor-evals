## Verdict
Exploitable. Untrusted HTTP request parameter flows directly into an OS command string without validation or escaping, enabling arbitrary command injection.

## Source
`request.getParameter("name")` at Case05A.java:16, passed through Case05B and Case05C unchanged to the sink.

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

// VULNERABLE: user input concatenated into command string
Process process = Runtime.getRuntime().exec(osCommand + data);
process.waitFor();
```

**Fixed code:**
```java
// Input validation: prevent argument injection (CWE-88)
if (data == null || data.startsWith("-")) {
    throw new IllegalArgumentException("Invalid directory argument");
}

ProcessBuilder pb;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
{
    // Use ProcessBuilder with separate arguments instead of concatenated string
    pb = new ProcessBuilder("cmd.exe", "/c", "dir", data);
}
else
{
    // Use ProcessBuilder with separate arguments instead of concatenated string
    pb = new ProcessBuilder("ls", data);
}

Process process = pb.start();
process.waitFor();
```

## Explanation
The fix replaces `Runtime.exec(String)` with `ProcessBuilder` initialized with separate argument arrays. `Runtime.exec(String)` uses `StringTokenizer` to split the concatenated string, which allows shell metacharacters (`;`, `|`, `&&`, etc.) in user input to be interpreted as command separators. `ProcessBuilder` passes arguments directly without shell parsing, preventing metacharacter injection. Input validation is added to reject values starting with `-`, preventing argument injection where a value could be mistaken for a flag by the target program (`ls` or `dir`). The fix preserves the original behavior: spawning a process and waiting for completion without consuming output.

## Behaviour changes
1. **Input validation added**: Rejects `null` or values starting with `-` to prevent argument injection (CWE-88), per guidance. Original code had no validation; this may reject previously accepted inputs.
2. **ProcessBuilder initialization**: Changes from single-string invocation to separate argument array. No functional change; prevents shell tokenization vulnerability.
3. **Argument passing**: `data` is now passed as a separate argument element rather than concatenated. No functional change; enables direct command invocation.
4. **Process contract unchanged**: Still returns a `Process` object; still calls `waitFor()` to block; still does not consume output streams or return values; still throws IOException on execution failure.
