## Verdict
Confirmed OS command injection vulnerability via unsanitized query parameter concatenation into shell command.

## Source
The `host` query parameter (line 11) is directly concatenated into the `Arguments` string at line 16 without validation or escaping. Because `cmd.exe` is used as the shell interpreter (`FileName = "cmd.exe"`), an attacker can inject shell metacharacters (`&`, `|`, `;`, etc.) to execute arbitrary commands.

Example attack: `?host=8.8.8.8 & del /s /q C:\*` would delete files after the ping attempt.

## Fix
Replace the shell-based invocation with a direct call to `ping.exe`, passing the hostname as a structured argument instead of concatenating it into a command string:

```csharp
var psi = new ProcessStartInfo
{
    FileName = "ping.exe",
    Arguments = "-n 4 " + host,
    UseShellExecute = false,
    RedirectStandardOutput = true
};

using var process = Process.Start(psi);
```

Alternatively, if structured arguments are available, use an `ArgumentList` collection (available in .NET 6+):

```csharp
var psi = new ProcessStartInfo
{
    FileName = "ping.exe",
    UseShellExecute = false,
    RedirectStandardOutput = true
};
psi.ArgumentList.Add("-n");
psi.ArgumentList.Add("4");
psi.ArgumentList.Add(host);

using var process = Process.Start(psi);
```

## Explanation
When `FileName` is `cmd.exe` and `UseShellExecute` is `false`, the Windows process launcher still invokes the shell interpreter for argument parsing, allowing metacharacters to be interpreted as command separators. By calling `ping.exe` directly as the FileName, arguments are passed to the ping process itself without shell interpretation. The second approach using `ArgumentList` is safer and is the recommended pattern for .NET 6+ because arguments are passed as an array rather than a string, preventing shell metacharacter interpretation entirely.
