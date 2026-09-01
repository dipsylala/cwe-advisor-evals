## Verdict

CWE-78 confirmed. The `data` parameter is concatenated directly into a command string and passed to `Runtime.exec()`, allowing command injection.

## Source

Case15A.java:16 – `data = "foo"` (parameter, in real usage untrusted)
Case15B.java:11 – `data` parameter accepted without validation
Case15B.java:28 – `data` concatenated into command string and passed to `Runtime.exec()`

## Fix

```java
public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
{
    ProcessBuilder pb;
    if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
    {
        pb = new ProcessBuilder("cmd.exe", "/c", "dir", data);
    }
    else
    {
        pb = new ProcessBuilder("/bin/ls", data);
    }

    Process process = pb.start();
    process.waitFor();
}
```

## Explanation

The original code concatenated `data` into a command string and passed it to `Runtime.exec(String)`, which tokenizes the string and passes it to the shell. Special characters in `data` (`;`, `|`, `&`, etc.) are interpreted as command separators, allowing arbitrary command injection.

The fix replaces `Runtime.exec(String)` with `ProcessBuilder` and passes the command and arguments as separate list elements. This prevents the shell from interpreting special characters in `data` as command metacharacters—`data` is passed as a single argument value to the target process, not re-parsed by a shell.

The fix preserves the original behavior: `Runtime.exec()` is still used (indirectly through `ProcessBuilder.start()`), the process return value is handled identically (`process.waitFor()`), and no output is discarded.

## Behaviour changes

- `Runtime.getRuntime().exec(String)` (string concatenation) → `ProcessBuilder` with argument list (separate arguments)
- No change to process invocation purpose, return handling, or error semantics
- Shell metacharacters in the `data` argument are no longer interpreted as command separators
