## Verdict

**Confirmed.** The `statusMessage` parameter, sourced from untrusted HTTP form input and concatenated directly into a Redis wire protocol command without validation, can be exploited to inject additional Redis commands. An attacker can inject CRLF characters followed by malicious Redis operations.

## Source

Lines 21–27. The `statusMessage` parameter is received from HTTP form data (`[FromForm] string statusMessage`) with no validation, then concatenated directly into the Redis command string on line 27. This permits an attacker to supply a value like `"newstatus\r\nDEL presence:*\r\n"` which, when sent to Redis, will be interpreted as two separate commands: `SET` followed by `DEL`.

## Fix

Replace raw socket communication with a Redis client library. Use `StackExchange.Redis`, which constructs protocol-compliant commands and automatically handles argument encoding:

```csharp
using System.Net.Sockets;
using System.Text;
using StackExchange.Redis;
using Microsoft.AspNetCore.Mvc;

namespace PresenceService.Controllers;

[ApiController]
[Route("api/presence")]
public class PresenceController : ControllerBase
{
    private readonly IDatabase _redisDb;

    public PresenceController(IConnectionMultiplexer redis)
    {
        _redisDb = redis.GetDatabase();
    }

    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        if (string.IsNullOrEmpty(statusMessage))
            return BadRequest("Missing statusMessage");

        string redisKey = "presence:" + userId;
        _redisDb.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

## Explanation

Raw socket communication with manually constructed protocol strings is vulnerable to injection because CRLF characters in user input become command delimiters when sent to Redis. The fix uses `StackExchange.Redis` client library, which encodes arguments using the Redis Serialization Protocol (RESP) array format. This format separates command arguments by length-prefixed boundaries rather than delimiters, making command injection impossible—the `statusMessage` value is treated as a data argument regardless of its content.

The secondary change adds validation for the `statusMessage` to prevent empty values from being stored.
