## Verdict

Exploitable. Confidence: high.

- CWE ID: CWE-77 (Improper Neutralization of Special Elements used in a Command)
- Location: `RedisSetRawSocket.cs`, line 31 (`_redisSocket.Send(payload)`)
- Library recommendation: StackExchange.Redis. The loaded guidance supplies no minimum safe version for this fix, so none is given here - confirm the resolved version against SCA/dependency-check tooling before merging.

## Source

Two HTTP-request-supplied values reach the sink without neutralization:

- `statusMessage`, bound via `[FromForm]` on `UpdateStatus` - free-form, attacker-controlled, no length or character-set constraint.
- `userId`, bound from the request on the same action - only checked for null/empty (`string.IsNullOrEmpty`), otherwise unconstrained.

Both flow directly into the command string built at line 27 (`"SET " + redisKey + " " + statusMessage + "\r\n"`, where `redisKey = "presence:" + userId`), which is then encoded to ASCII bytes and written raw to the shared Redis socket at line 31. Because this is Redis's plain-text inline protocol, an embedded `\r\n` in either value terminates the intended `SET` command and starts a new one that the Redis server will execute - e.g. `statusMessage` of `"ok\r\nFLUSHALL\r\n"` sends a second, attacker-chosen command on the shared connection.

## Fix

Vulnerable code:

```csharp
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace PresenceService.Controllers;

[ApiController]
[Route("api/presence")]
public class PresenceController : ControllerBase
{
    private readonly Socket _redisSocket;

    public PresenceController(Socket redisSocket)
    {
        _redisSocket = redisSocket;
    }

    // Updates a user's presence status ("away", "busy", custom message) by
    // writing directly to the Redis wire protocol on the shared socket.
    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        string redisKey = "presence:" + userId;
        string command = "SET " + redisKey + " " + statusMessage + "\r\n";
        byte[] payload = Encoding.ASCII.GetBytes(command);

        // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
        _redisSocket.Send(payload);

        return Ok();
    }
}
```

Fixed code:

```csharp
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;

namespace PresenceService.Controllers;

[ApiController]
[Route("api/presence")]
public class PresenceController : ControllerBase
{
    private readonly IDatabase _redisDb;

    public PresenceController(IDatabase redisDb)
    {
        _redisDb = redisDb;
    }

    // Updates a user's presence status ("away", "busy", custom message)
    // using StackExchange.Redis's parameterized command API.
    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        string redisKey = "presence:" + userId;
        _redisDb.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

## Explanation

The vulnerability is in how the command was framed, not in the values themselves: hand-building `"SET " + redisKey + " " + statusMessage + "\r\n"` and writing it to a raw `Socket` uses Redis's plain-text inline protocol, where `\r\n` is the only thing separating one command from the next - any attacker-controlled `\r\n` in `userId` or `statusMessage` is indistinguishable from the framing the application itself inserted. The fix replaces the raw socket and hand-built command string with StackExchange.Redis's `IDatabase.StringSet(key, value)`, which sends the key and value as separate RESP-encoded arguments, each carrying an explicit length prefix rather than being terminated by a delimiter character. A length-prefixed argument cannot be split by an embedded CRLF, space, or any other byte sequence, so both `redisKey` and `statusMessage` reach Redis as literal data regardless of content, closing the injection point at its source (the framing mechanism) rather than by trying to sanitize the values.

## Behaviour changes

- The constructor now takes `IDatabase` instead of `Socket`. This requires the composition root to register StackExchange.Redis's `ConnectionMultiplexer`/`IDatabase` and resolve it via DI in place of whatever previously supplied the shared `Socket`. This is required by the fix: the primary defence is the client library's RESP framing, which is not available on a raw `Socket`, so the dependency swap is not optional.
- The command is now sent via `IDatabase.StringSet(redisKey, statusMessage)` instead of a hand-assembled inline-protocol byte payload over `Socket.Send`. Required to eliminate the injection point; `StringSet` discards its `bool` result (whether the key was newly set) exactly as the original code discarded any acknowledgement from `Send`, so no additional information is surfaced or lost.
- Failure behaviour changes type, not presence: the original `Socket.Send` would throw `SocketException` on a connection problem, uncaught, propagating to ASP.NET Core's default error handling. `IDatabase.StringSet` throws `RedisConnectionException` or `RedisTimeoutException` instead, also uncaught here - the method still has no try/catch, so error handling is unchanged in kind (unhandled, propagates), only in exception type.
- No expiry (`TTL`) was set on the key in the original code, and none is added here - `StringSet` is called with its expiry parameter left at the default (no expiry), matching the original's unbounded `SET` with no `EX`/`PX`. If presence entries are meant to expire, that is a separate, pre-existing gap this fix does not address.
- Character-set/length validation on `userId` and `statusMessage` was not added. StackExchange.Redis's parameterized API already closes the injection regardless of content, so this would be additional defence-in-depth rather than something required to close the finding; it is not applied here to keep the change scoped to the reported weakness.
