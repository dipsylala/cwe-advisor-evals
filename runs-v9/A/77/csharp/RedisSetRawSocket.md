## Verdict

Confirmed. `UpdateStatus` builds a Redis inline command by concatenating unvalidated request data (`userId` from the route/query, `statusMessage` from the form body) into a single `SET key value\r\n` string and writes the raw bytes straight onto the shared Redis socket. Redis's inline command format has no quoting or escaping rule for embedded whitespace or `\r\n` — either parameter can inject additional arguments or additional commands into the same connection.

## Source

- `userId` — `UpdateStatus(string userId, ...)`, bound from the request (route/query string), line 21.
- `statusMessage` — `[FromForm] string statusMessage`, bound from the POST form body, line 21.

Both flow unmodified into `command` at line 27 and are transmitted as the command interpreter's input at the sink, `_redisSocket.Send(payload)`, line 31.

## Fix

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
    private readonly IDatabase _redisDb;

    public PresenceController(IConnectionMultiplexer redisConnection)
    {
        _redisDb = redisConnection.GetDatabase();
    }

    // Updates a user's presence status ("away", "busy", custom message) using
    // a Redis client that encodes arguments as binary-safe RESP bulk strings.
    [HttpPost("status")]
    public async Task<IActionResult> UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        RedisKey redisKey = "presence:" + userId;
        await _redisDb.StringSetAsync(redisKey, statusMessage);

        return Ok();
    }
}
```

Replace the hand-rolled socket with a maintained Redis client — `StackExchange.Redis` (register `IConnectionMultiplexer` via DI, e.g. `ConnectionMultiplexer.Connect(...)` as a singleton) is the standard choice for .NET. Call `IDatabase.StringSetAsync(RedisKey, RedisValue)` instead of building `"SET key value\r\n"` by hand. The client serializes each argument as its own length-prefixed RESP bulk string, so embedded spaces, `\r`, or `\n` in `userId` or `statusMessage` become literal bytes inside that argument's payload — they cannot terminate the command early or introduce a second command, regardless of content.

As defense in depth, also constrain `userId` to the character set your key namespace expects (e.g. an allowlist of alphanumerics/hyphen) before building `redisKey`, so a malformed identifier is rejected with a 400 rather than silently becoming part of a Redis key.

## Explanation

Redis's inline command protocol delimits both the argument list and the end of the command using whitespace and `\r\n`. When a raw string is assembled by concatenation and written directly to the socket, any `\r\n` sequence the attacker places in `statusMessage` ends the current `SET` command and starts a new one on the same connection — for example a value of `x\r\nFLUSHALL\r\n` (or `CONFIG`, `EVAL`, etc., depending on what the connection is authorized to run) executes as a second, independent command against the shared Redis connection. A space in either field silently shifts which token is treated as the key versus the value. This is command injection against the Redis wire-protocol interpreter, structurally identical to SQL injection against a SQL interpreter: the fix is not to blocklist `\r\n`, but to stop building the protocol frame by string concatenation at all. `StackExchange.Redis` (or any client implementing the RESP protocol) already sends each argument as a length-prefixed bulk string — the transport format itself has no delimiter that user-controlled bytes can forge, so switching to it closes the injection class rather than filtering specific bytes.
