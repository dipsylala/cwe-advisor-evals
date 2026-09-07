## Verdict

The finding is **CONFIRMED**. The code constructs a raw Redis inline protocol command via string concatenation, allowing an attacker to inject arbitrary Redis commands by including CRLF sequences in the `statusMessage` input. For example, a statusMessage of `away\r\nFLUSHALL\r\n` would be interpreted as two commands: `SET presence:userId away` followed by `FLUSHALL`, bypassing intended data operations.

## Source

- **Primary source:** `statusMessage` parameter (line 21), marked `[FromForm]` as untrusted HTTP request data
- **Secondary source:** `userId` parameter (line 21), also untrusted HTTP request data
- **Data flow:** Both inputs flow unsanitized into the command string constructed at line 27, which is then sent to Redis via raw socket at line 31
- **Sink:** `_redisSocket.Send(payload)` at line 31, which transmits the raw inline protocol bytes directly to Redis

## Fix

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
    // writing to Redis using the parameterized API.
    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        string redisKey = "presence:" + userId;
        
        // Use StackExchange.Redis's parameterized API to prevent command injection.
        // The client library encodes each argument with a length prefix,
        // so embedded delimiters cannot be interpreted as command separators.
        _redisDatabase.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

## Explanation

The vulnerability stems from building Redis commands via string concatenation without escaping. The Redis inline protocol treats CRLF (`\r\n`) as a command terminator and statement separator, allowing an attacker to inject complete commands.

The fix replaces the raw socket approach with StackExchange.Redis, the standard .NET Redis client library. This library automatically uses the RESP (Redis Serialization Protocol), which encodes each argument with an explicit length prefix. Under RESP, the length prefix tells Redis the exact byte count to consume for each argument, so embedded CRLF, spaces, and other delimiters are treated as literal data rather than protocol syntax. The same value that would terminate a command in inline protocol becomes harmless data in RESP.

The parameterized `StringSet(key, value)` method accepts the key and value as separate parameters, ensuring they are encoded as distinct RESP array elements. Even if `statusMessage` contains `\r\nFLUSHALL\r\n`, it will be stored as literal data, not executed as a separate command.

**Dependency:** StackExchange.Redis is a NuGet package (`StackExchange.Redis`) maintained by the community and widely used in production .NET applications. Confirm the version used is current via dependency scanning tooling before merging.

## Behaviour changes

- **Dependency injection model:** Constructor changes from accepting a raw `Socket` to accepting `IConnectionMultiplexer` (the StackExchange.Redis connection abstraction). This allows the Redis connection to be managed centrally, with connection pooling and automatic failover handled by the library.
- **Protocol change:** The fix switches from inline protocol (human-readable, space-separated commands terminated by CRLF) to RESP (binary length-prefixed encoding). Both set the same key-value pair at the Redis server; the RESP approach prevents delimiter injection.
- **Removed fields/using statements:** The raw `_redisSocket` field is no longer needed. Unused `using System.Net.Sockets` and `using System.Text` directives were removed, and `using StackExchange.Redis` was added.
- **Removed encoding step:** The code no longer manually encodes the command string to ASCII bytes—the client library handles this.
- **Identical business logic:** The HTTP endpoint still accepts `userId` and `statusMessage`, validates the presence of `userId`, constructs the same Redis key (`presence:{userId}`), and returns `Ok()` on success. Legitimate input behaves identically.
