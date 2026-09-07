## Verdict

VULNERABLE. Untrusted user input (`statusMessage`) is concatenated into a Redis command string and sent over a raw socket using the inline protocol. The inline protocol is CRLF-delimited, so embedded newlines allow command injection.

## Source

HTTP POST parameter `statusMessage` (line 21, `[FromForm] string statusMessage`)

## Fix

Replace the raw socket code with StackExchange.Redis's parameterized `Execute()` API:

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
    private readonly IConnectionMultiplexer _redis;

    public PresenceController(IConnectionMultiplexer redis)
    {
        _redis = redis;
    }

    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        string redisKey = "presence:" + userId;
        
        // Use StackExchange.Redis's typed API with length-delimited arguments.
        // The RESP protocol encodes each argument with a length prefix,
        // preventing embedded CRLF from being interpreted as a new command.
        var db = _redis.GetDatabase();
        db.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

**Changes:**
- Replaced `Socket _redisSocket` with `IConnectionMultiplexer _redis` (StackExchange.Redis connection)
- Replaced constructor parameter from `Socket` to `IConnectionMultiplexer`
- Replaced raw socket string-building + Send with `db.StringSet(redisKey, statusMessage)`
- Added `using StackExchange.Redis;` import

**Dependencies:**
- StackExchange.Redis (add to project via NuGet; version determined by SCA tooling; no known unfixed CVE)

## Explanation

The original code builds a Redis command by concatenating untrusted input into a string: `"SET " + redisKey + " " + statusMessage + "\r\n"`. The Redis inline protocol (plain-text TCP) interprets CRLF as a command terminator, so a statusMessage containing `\r\n` splits into multiple commands on the wire. An attacker could inject `value\r\nFLUSHALL\r\n` to execute `FLUSHALL` after setting the key.

StackExchange.Redis uses the RESP (REdis Serialization Protocol), which encodes each argument with an explicit length prefix (`$<length>\r\n<data>\r\n`). In RESP, embedded CRLF or spaces in a value are part of the data, not delimiters, so `StringSet()` safely transmits the statusMessage as-is. The library handles framing; the attacker cannot escape it.

## Behaviour changes

- **Wire protocol:** Switches from inline protocol (plain-text, CRLF-delimited) to RESP (binary-safe, length-prefixed). Both are valid Redis protocols; RESP is preferred by all modern clients.
- **Connection:** Switches from raw `Socket` to `IConnectionMultiplexer`, which pools and manages connections, handles reconnection, and is the standard .NET Redis client interface.
- **Return value:** `StringSet()` returns a bool indicating success; the original code discarded the socket's Send return value. Error handling is simpler with the client library (throws on error) than manual socket management.
- **Dependency:** Adds StackExchange.Redis as a required dependency.

