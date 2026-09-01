## Verdict
Exploitable. The `host` query parameter flows directly into the command string without validation or escaping, allowing shell metacharacter injection via Process.Start() with cmd.exe.

## Source
`[FromQuery] string host` parameter (line 11) - user-controlled query string input

## Fix

**Vulnerable code (line 13-22):**
```csharp
var psi = new ProcessStartInfo
{
    FileName = "cmd.exe",
    Arguments = "/c ping -n 4 " + host,
    UseShellExecute = false,
    RedirectStandardOutput = true
};

// SAST FINDING: CWE-78 - OS Command Injection
using var process = Process.Start(psi);
```

**Fixed code:**
```csharp
if (string.IsNullOrWhiteSpace(host))
{
    return BadRequest("Host parameter is required.");
}

try
{
    using var ping = new Ping();
    var reply = ping.Send(host, timeout: 5000);

    var output = reply.Status == IPStatus.Success
        ? $"Reply from {reply.Address}: bytes={reply.Buffer.Length} time={reply.RoundtripTime}ms TTL={reply.Options?.Ttl}"
        : $"Ping failed: {reply.Status}";

    return Content(output, "text/plain");
}
catch (ArgumentException ex)
{
    return BadRequest($"Invalid host: {ex.Message}");
}
```

Add `using System.Net.NetworkInformation;` to the imports at the top of the file.

## Explanation
The vulnerability arises because the user-controlled `host` parameter is concatenated directly into a command string that is passed to cmd.exe with the `/c` flag. This allows an attacker to inject shell metacharacters (e.g., `&`, `|`, `;`) to execute arbitrary commands. The fix replaces the process-based ping invocation with the .NET Framework's `System.Net.NetworkInformation.Ping` class, which eliminates the command shell entirely. This is the primary remediation pattern for CWE-78 in C#: use language-native APIs instead of shelling out to external commands. The Ping class provides the same functionality—sending ICMP echo requests and receiving responses—without the injection risk. Input validation is added as a secondary layer to reject empty or null host values.

## Behaviour changes

1. **Return type for network failures**: The original code silently captured command output including error messages from the ping executable. The fixed code explicitly handles different IPStatus values and returns formatted success/failure messages. This is a justified change because it avoids information disclosure from uncontrolled command output.

2. **Timeout handling**: The original ping command uses the system default timeout behavior. The fixed code explicitly sets a 5000ms timeout on `Ping.Send()` to prevent indefinite hangs. This is a safety improvement.

3. **Exception handling**: The original code would crash on invalid hostnames or network errors. The fixed code catches `ArgumentException` (invalid hostname) and returns a user-friendly error response. This improves robustness.

4. **Input validation**: The fixed code validates that the host parameter is not null or whitespace and returns a 400 BadRequest if missing. This was not present in the original code.

All other behaviour is preserved: both versions return ping results as plain text via HTTP Content response, and both perform network diagnostics on a user-supplied host.
