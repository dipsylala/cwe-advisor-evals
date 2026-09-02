## Verdict

**OS Command Injection via shell interpolation.** The user-controlled `host` parameter is interpolated directly into a shell command string passed to `sh -c`, allowing an attacker to inject arbitrary shell metacharacters and commands. The vulnerability is at line 18, where the unsanitized command line is executed.

## Source

Line 16 constructs the command:
```
cmdLine := fmt.Sprintf("traceroute -m 15 %s", host)
```

The `host` value comes from the untrusted query parameter (`r.URL.Query().Get("host")` at line 10) with only a presence check, no input validation. This string is then passed to the shell at line 18:
```
cmd := exec.Command("sh", "-c", cmdLine)
```

An attacker can inject shell operators: `host=8.8.8.8 ; rm -rf /` or `host=8.8.8.8 | cat /etc/passwd` will execute arbitrary commands in the shell context.

## Fix

Replace the shell-based invocation with direct argument passing:

```go
cmd := exec.Command("traceroute", "-m", "15", host)
```

This passes `host` as a literal argument to the `traceroute` binary, bypassing shell interpretation entirely. Shell metacharacters in the hostname are treated as literal characters in the argument, not as command separators or operators.

## Explanation

OS Command Injection occurs when user input is embedded into a command that is then interpreted by a shell. The vulnerability chain is: unsanitized user input → shell command string → `sh -c` execution.

The fix eliminates the shell layer by calling `exec.Command()` with separate arguments. Go's `exec` package passes arguments directly to the target program without shell parsing, so special characters in user input cannot break out to execute additional commands.

This approach is safer than attempting to escape special characters, because escaping rules vary by shell and context; removing the shell interpreter eliminates the parsing step entirely.
