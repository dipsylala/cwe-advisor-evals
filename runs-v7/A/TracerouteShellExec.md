## Verdict
Confirmed: CWE-78 OS Command Injection via unsanitized user input passed to shell.

## Source
Line 10: `host := r.URL.Query().Get("host")` retrieves user-controlled input from HTTP query parameter without validation.

## Fix
Replace the shell invocation with direct argument passing to avoid shell metacharacter interpretation:

```go
cmd := exec.Command("traceroute", "-m", "15", host)
```

This passes `host` as a direct argument to `traceroute` rather than concatenating it into a shell command string.

## Explanation
The vulnerability exists because line 16 concatenates the untrusted `host` parameter into a command string that is then executed via `sh -c` (line 18). A shell interpreter processes this string, allowing an attacker to inject shell metacharacters. For example, a `host` value of `localhost; rm -rf /` would execute both the `traceroute` command and the injected `rm` command.

Using `exec.Command()` with separate arguments bypasses the shell entirely. Each argument is passed directly to the target program (`traceroute`), where special characters are treated as literal data rather than command syntax. This is the primary defense against OS command injection: avoid shell interpretation of attacker-controlled data.
