## Verdict
exploitable

## Source
`statusMessage` parameter from HTTP request (injected via `[FromForm]` attribute) - untrusted user input that reaches the Redis command string without neutralization.

## Fix

**Vulnerable code:**
```csharp
public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
{
    if (string.IsNullOrEmpty(userId))
        return BadRequest("Missing userId");

    string redisKey = "presence:" + userId;
    string command = "SET " + redisKey + " " + statusMessage + "\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);
    
    // Sink - CWE-77 vulnerability: statusMessage is concatenated into a raw Redis
    // inline-protocol command without escaping, allowing injection of CRLF and
    // arbitrary Redis commands.
    _redisSocket.Send(payload);

    return Ok();
}
```

**Fixed code:**
```csharp
private readonly IConnectionMultiplexer _redisConnection;

public PresenceController(IConnectionMultiplexer redisConnection)
{
    _redisConnection = redisConnection;
}

[HttpPost("status")]
public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
{
    if (string.IsNullOrEmpty(userId))
        return BadRequest("Missing userId");

    string redisKey = "presence:" + userId;
    
    // Use StackExchange.Redis's parameterized StringSet API instead of hand-building
    // a raw command string. The RESP protocol encodes each argument with an explicit
    // length prefix, so embedded CRLF in statusMessage cannot be interpreted as a
    // command separator.
    IDatabase db = _redisConnection.GetDatabase();
    db.StringSet(redisKey, statusMessage);

    return Ok();
}
```

## Explanation
The original code builds a raw Redis inline-protocol command by string concatenation, then sends it over a raw socket. The Redis inline protocol terminates commands with CRLF (`\r\n`), so if `statusMessage` contains `\r\n`, an attacker can inject arbitrary Redis commands. For example, a payload of `"test\r\nFLUSHALL\r\n"` would execute two separate commands: `SET presence:user123 test` and then `FLUSHALL`, potentially destroying all Redis data. The fix replaces the raw socket and hand-built command string with StackExchange.Redis's `IDatabase.StringSet()` method. This library frames each argument with an explicit length prefix using the RESP (Redis Serialization Protocol), so delimiters within the value are treated as literal data and cannot split into a new command. The change also makes error handling explicit: `StringSet()` returns a boolean indicating success, whereas the original code ignored whether the socket send succeeded.

## Behaviour changes
- **Dependency injection changes from `Socket` to `IConnectionMultiplexer`**: The original code received a raw socket. The fixed code requires StackExchange.Redis's connection multiplexer, which manages pooling, reconnection, and protocol handling. This is a required change to close the vulnerability. The dependency must be added to the project: add the NuGet package `StackExchange.Redis` (version per SCA/dependency-check tooling before merging).
- **Return value and error handling**: The original `Socket.Send()` was not checked for success or failure. The fixed code's `StringSet()` returns a boolean; the updated code should check this return value and handle failure (e.g., return an error response to the client or log the failure). This is a safety improvement, not a regression.
- **Command execution model**: The original code sent bytes directly over the socket with no client-side protocol handling. The fixed code uses the client library's serialization, which adds minimal overhead and is the recommended pattern for Redis communication from .NET.
