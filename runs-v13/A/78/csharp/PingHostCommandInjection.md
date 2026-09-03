## Verdict

Real. The `host` parameter is directly concatenated into a shell command string without validation or escaping, enabling arbitrary command injection through the OS command interpreter.

## Source

The vulnerable operation is at line 16, where user-supplied input flows directly into the command:

```csharp
Arguments = "/c ping -n 4 " + host,
```

An attacker controlling the `host` query parameter can inject additional shell metacharacters and commands. For example, `host=8.8.8.8 & dir C:\` would execute both the ping and a directory listing.

## Fix

Replace the shell-based invocation with a direct call to `ping.exe`, passing the hostname as a separate argument rather than concatenating it into a shell command string:

```csharp
var psi = new ProcessStartInfo
{
    FileName = "ping.exe",
    Arguments = "-n 4 " + host,
    UseShellExecute = false,
    RedirectStandardOutput = true
};
```

This removes the shell interpreter as a vector for injection. The `ping.exe` process does not treat its argument string as containing shell syntax, so metacharacters like `&`, `|`, `;`, and `>` are passed literally to the ping utility, which rejects them as invalid hostnames.

## Explanation

The root cause is invoking a shell (`cmd.exe /c`) to run the ping command. Shell interpreters parse their input for metacharacters, so any special character in the user-supplied hostname becomes a potential injection point for additional commands.

Moving from shell-based execution to direct binary invocation eliminates this risk. The `ping.exe` process receives its arguments as a list, not as a shell string, so it has no mechanism to interpret metacharacters as command separators or operators. An invalid hostname simply causes `ping.exe` to fail with a lookup error, rather than executing attacker-supplied logic.

The fix preserves the original functionality (pinging a host with 4 packets) while removing the injection surface. `UseShellExecute = false` remains set, which ensures the arguments are not further interpreted by any shell, and `RedirectStandardOutput` continues to capture the ping output for the HTTP response.
