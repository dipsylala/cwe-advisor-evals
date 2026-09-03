## Verdict

**CONFIRMED**: OS Command Injection via unsafe string concatenation in `Runtime.getRuntime().exec()`.

## Source

**File**: `Case15B.java`, Line 28  
**Location**: `handleSink()` method

The vulnerability exists because:
1. User-controlled `data` parameter is concatenated directly with the command string: `osCommand + data`
2. The concatenated string is passed to `Runtime.getRuntime().exec()` as a single string argument
3. When `exec()` receives a single string, it tokenizes the input using shell parsing rules, interpreting shell metacharacters in `data`
4. An attacker can inject shell operators (`;`, `|`, `&&`, etc.) to break out of the intended command and execute arbitrary commands

**Call chain**: `Case15A.handle()` → `Case15B.handleSink()` with unsanitized `data` parameter.

## Fix

Replace the vulnerable string concatenation with an argument array passed to `exec()`:

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

## Explanation

The key difference between the vulnerable and fixed code:

- **Vulnerable**: `Runtime.getRuntime().exec(osCommand + data)` passes a single string that undergoes shell tokenization
- **Fixed**: `Runtime.getRuntime().exec(String[] cmdarray)` passes arguments as an array, preventing shell metacharacter interpretation

When `exec()` receives a string array, each element is treated as a separate argument without shell parsing. This means that even if `data` contains shell metacharacters or operators, they are passed literally to the target command (`dir` or `ls`) and are not interpreted as command separators or options. The target command receives them as literal filename arguments, which it then safely interprets (or rejects as invalid filenames).

This approach is the standard Java defense for OS command injection and is recommended in the Java security documentation and OWASP guidance.
