## Verdict

**CONFIRMED.** CWE-77 command injection vulnerability. The `statusMessage` parameter from the HTTP POST request is concatenated directly into a Redis inline-protocol command string without sanitization. An attacker can inject CRLF characters (`\r\n`) to terminate the SET command and inject arbitrary Redis commands (e.g., `value\r\nFLUSHALL\r\n`). The `userId` parameter has insufficient validation—it is only checked for null/empty—and is also vulnerable to the same injection pattern. The sink is `Socket.Send()` at line 31, which transmits the unsanitized command to Redis.

## Source

- **Input:** `statusMessage` parameter from HTTP POST request (user-supplied, attacker-controlled)
- **Secondary input:** `userId` parameter (validated only for null/empty, insufficient against CRLF injection)
- **Entry point:** `UpdateStatus()` method, line 21

## Fix

The vulnerability is eliminated by replacing the raw `Socket` communication and hand-built command strings with the StackExchange.Redis client library's parameterized API. The RESP protocol used by StackExchange.Redis encodes each argument with an explicit length prefix, preventing embedded CRLF or spaces from being interpreted as command or argument separators.

### File: RedisSetRawSocket.cs

```csharp
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;

namespace PresenceService.Controllers;

[ApiController]
[Route("api/presence")]
public class PresenceController : ControllerBase
{
    private readonly IDatabase _redisDatabase;

    public PresenceController(IConnectionMultiplexer redisConnection)
    {
        _redisDatabase = redisConnection.GetDatabase();
    }

    // Updates a user's presence status ("away", "busy", custom message) by
    // using the Redis client library's typed API to safely write the key-value pair.
    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        if (string.IsNullOrEmpty(statusMessage))
            return BadRequest("Missing statusMessage");

        // Validate userId: allowlist alphanumeric, hyphen, underscore only
        if (!System.Text.RegularExpressions.Regex.IsMatch(userId, @"\A[a-zA-Z0-9_-]+\z"))
            return BadRequest("Invalid userId format");

        string redisKey = "presence:" + userId;

        // Safe pattern: Use StackExchange.Redis's typed StringSet() method.
        // The client library encodes each argument using RESP protocol length prefixes,
        // preventing CRLF injection. The statusMessage value is sent as data, not as a command.
        _redisDatabase.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

## Explanation

The original code built a Redis command string via concatenation (`"SET " + redisKey + " " + statusMessage + "\r\n"`) and sent it over a raw socket using the inline protocol. The inline protocol is CRLF-terminated and space-delimited, so an embedded `\r\n` is treated as a command separator, allowing injection of arbitrary commands.

The fixed code replaces this approach with StackExchange.Redis's `IDatabase.StringSet()` method. This method:

1. Uses the RESP (Redis Serialization Protocol) format, which encodes each argument with an explicit byte-length prefix (e.g., `$5\r\nvalue\r\n`).
2. Separates the command name from each argument in a way that length prefixes guarantee no embedded data can be misinterpreted as a delimiter.
3. Eliminates the need to concatenate untrusted values into command strings.

Additionally, the fix validates `userId` using an allowlist pattern (`@"\A[a-zA-Z0-9_-]+\z"`) to reject any value containing CRLF, space, or other problematic characters. The regex uses `\A` and `\z` anchors (not `^` and `$`) to ensure the pattern matches the entire string regardless of line terminators in the regex engine's interpretation—addressing the general principle in CWE-77 guidance about anchoring validation properly in .NET.

The dependency changes from `Socket` (raw socket, requires manual protocol handling) to `IConnectionMultiplexer` (StackExchange.Redis connection manager), which is a standard dependency in .NET Redis applications.

## Behaviour changes

- **Constructor dependency:** Changed from `Socket redisSocket` to `IConnectionMultiplexer redisConnection`. The application's DI configuration must provide an `IConnectionMultiplexer` (via `services.AddStackExchangeRedisCache()` or manual `ConnectionMultiplexer.Connect()`) instead of a raw socket.
- **No return values change:** `StringSet()` returns a bool indicating success (vs. the original `Send()` return), but the code ignores both, so observable return behavior is unchanged.
- **Protocol format:** Commands now use RESP format instead of inline protocol. Redis servers support both, so this is compatible with all Redis versions; however, the wire protocol bytes differ.
- **Input validation strengthened:** Added a null/empty check for `statusMessage` and an allowlist pattern validation for `userId`. These are defensive additions that may reject some previously accepted but malformed inputs.
- **No implicit arguments:** `StringSet()` uses default parameters (no expiration, unconditional SET without options), which matches the original code's behavior (the original sent a simple SET with no TTL or flags).
