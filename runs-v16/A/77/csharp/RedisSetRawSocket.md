## Verdict

**CONFIRMED**: CWE-77 command injection via direct string concatenation into Redis wire protocol commands.

## Source

The `statusMessage` parameter on line 21 derives from untrusted user input via `[FromForm]`. On line 27, this value is concatenated directly into a Redis command string without sanitization or escaping:

```csharp
string command = "SET " + redisKey + " " + statusMessage + "\r\n";
```

An attacker can inject Redis protocol metacharacters (space, `\r\n`, etc.) to append arbitrary commands to the wire stream and execute them on the Redis server.

## Fix

Replace raw socket communication with the standard StackExchange.Redis client library, which handles Redis protocol encoding and command separation safely:

```csharp
using StackExchange.Redis;
using Microsoft.AspNetCore.Mvc;

namespace PresenceService.Controllers;

[ApiController]
[Route("api/presence")]
public class PresenceController : ControllerBase
{
    private readonly IDatabase _redis;

    public PresenceController(IConnectionMultiplexer connection)
    {
        _redis = connection.GetDatabase();
    }

    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        string redisKey = "presence:" + userId;
        _redis.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

## Explanation

The injected code uses `IConnectionMultiplexer` from StackExchange.Redis instead of a raw socket. The `StringSet` method constructs the Redis command using the RESP (REdis Serialization Protocol) wire format, where command and argument boundaries are encoded with length prefixes rather than whitespace delimiters. This prevents user input from being interpreted as command boundaries, even if it contains `\r\n`, spaces, or other Redis metacharacters.

StackExchange.Redis is the maintained, standard Redis client for C# and handles connection pooling, pipelining, and protocol compliance automatically. Dependency: `StackExchange.Redis` (version 2.6.0 or later).
