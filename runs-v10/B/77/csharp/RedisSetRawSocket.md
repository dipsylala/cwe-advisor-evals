## Verdict

Exploitable.

## Source

`statusMessage` (parameter from `UpdateStatus` method, line 21) and `userId` (parameter, line 21) - both controlled by the HTTP request and untrusted. The `statusMessage` is concatenated directly into the Redis inline protocol command string at line 27 without any neutralization of delimiter characters.

## Fix

**Vulnerable code (lines 26–31):**
```csharp
string redisKey = "presence:" + userId;
string command = "SET " + redisKey + " " + statusMessage + "\r\n";
byte[] payload = Encoding.ASCII.GetBytes(command);

// SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
_redisSocket.Send(payload);
```

**Fixed code:**

Replace the constructor and method to use StackExchange.Redis's parameterized API:

Constructor change:
```csharp
private readonly IDatabase _redisDb;

public PresenceController(IDatabase redisDb)
{
    _redisDb = redisDb;
}
```

Method fix (lines 20–34):
```csharp
[HttpPost("status")]
public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
{
    if (string.IsNullOrEmpty(userId))
        return BadRequest("Missing userId");
    
    if (string.IsNullOrEmpty(statusMessage))
        return BadRequest("Missing statusMessage");
    
    // Validate userId format as defence-in-depth: reject embedded delimiters
    if (!System.Text.RegularExpressions.Regex.IsMatch(userId, @"^\w+$"))
        return BadRequest("Invalid userId format");

    string redisKey = "presence:" + userId;
    
    // Use StackExchange.Redis StringSet for safe parameterized command execution.
    // The client library encodes arguments using RESP with explicit length prefixes,
    // preventing embedded CRLF or spaces from being read as command delimiters.
    _redisDb.StringSet(redisKey, statusMessage);

    return Ok();
}
```

## Explanation

The original code hand-builds a Redis inline protocol command by concatenating the `userId` and `statusMessage` directly into a string. Redis inline protocol is line-delimited: `\r\n` terminates the current command and begins a new one. An attacker can inject `\r\n` followed by arbitrary Redis commands (e.g., `value1\r\nFLUSHALL\r\n`) to execute commands beyond what the application intends. The fix replaces the raw `Socket` usage with StackExchange.Redis's `IDatabase.StringSet()` method, which encodes arguments using RESP (Redis Serialization Protocol). RESP prefixes each argument with its byte length, so embedded delimiters are literal data and cannot split commands. The userId validation (allowlist of word characters) provides defence-in-depth by rejecting unexpected formats. The dependency injection change substitutes `IDatabase` for `Socket`; the caller must wire StackExchange.Redis's `IConnectionMultiplexer` and pass an `IDatabase` instance.

## Behaviour changes

1. **Dependency injection contract change**: Constructor now requires `IDatabase` (from StackExchange.Redis) instead of `Socket`. The caller must instantiate and pass a multiplexer and database, not a raw socket. This is a breaking change to the component's interface, not a silent behavioural change within the current contract.

2. **Return value discarded**: `StringSet()` returns `bool` (success/failure) which is also discarded by the current code (matching the original `Send()` return contract). If error handling is needed, the caller should check the return value.

3. **Exception type on error**: The original code could throw `SocketException`; StackExchange.Redis may throw `RedisConnectionException`, `TimeoutException`, or return `false`. No try-catch guards either version, so this is a change in exception type but not in semantics (both surface errors to the caller).

4. **No other argument or output changes**: The `StringSet()` call achieves the same business outcome (storing the status message under a key) with the same parameters (key, value). The endpoint response remains `Ok()` on success.
