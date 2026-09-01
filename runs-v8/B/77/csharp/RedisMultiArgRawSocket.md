## Verdict

Exploitable. Untrusted input from the `agentNote` parameter is concatenated directly into a Redis inline-protocol command string and sent over a raw socket, allowing an attacker to inject additional Redis commands.

## Source

The `agentNote` parameter in the `SaveAgentNote` method receives untrusted data from a support ticket form without validation. An attacker can inject Redis command delimiters (`\r\n`) followed by arbitrary commands.

Example attack payload: `test note\r\nFLUSHALL\r\n` would result in two commands being sent:
1. `HSET session:... note test note`
2. `FLUSHALL`

## Fix

Replace the raw socket with StackExchange.Redis and use its parameterized `HashSet` API, which encodes each argument with explicit length prefixes so embedded delimiters cannot split into new commands:

**Vulnerable Code:**
```csharp
public class SessionNoteWriter
{
    private readonly Socket _redisSocket;

    public SessionNoteWriter(Socket redisSocket)
    {
        _redisSocket = redisSocket;
    }

    public void SaveAgentNote(string sessionId, string agentNote)
    {
        long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string command =
            "HSET session:" + sessionId +
            " note " + agentNote +
            " updated " + updatedAt +
            "\r\n";

        byte[] payload = Encoding.ASCII.GetBytes(command);
        _redisSocket.Send(payload);  // CWE-77: Command injection via untrusted agentNote
    }
}
```

**Fixed Code:**
```csharp
using StackExchange.Redis;

public class SessionNoteWriter
{
    private readonly IDatabase _redisDb;

    public SessionNoteWriter(IConnectionMultiplexer redis)
    {
        _redisDb = redis.GetDatabase();
    }

    public void SaveAgentNote(string sessionId, string agentNote)
    {
        long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        
        _redisDb.HashSet(
            "session:" + sessionId,
            new[] {
                new HashEntry("note", agentNote),
                new HashEntry("updated", updatedAt)
            });
    }
}
```

## Explanation

The fix replaces hand-built inline-protocol command concatenation with StackExchange.Redis's typed `HashSet` API. The StackExchange.Redis client uses the RESP protocol, which encodes each argument with an explicit byte-length prefix. This framing makes it impossible for an untrusted value containing `\r\n`, spaces, or Redis command names to be interpreted as command delimiters or separate commands. The `agentNote` value is now treated as literal data regardless of its content.

## Behaviour changes

- **Connection mode changed:** The code now uses `IConnectionMultiplexer` and `IDatabase` instead of a raw `Socket`. This trades direct socket control for protocol safety and connection pooling managed by the client library. The constructor now accepts an `IConnectionMultiplexer` (typically constructed once per application and injected as a dependency) rather than a `Socket`.

- **Return value:** The original `Socket.Send()` returns the number of bytes sent; `IDatabase.HashSet()` returns a `bool` indicating whether the operation succeeded. Code that relied on the byte count will need to handle or ignore the boolean result. If fire-and-forget semantics are required, `HashSetAsync()` can be used instead with a similar return type.

- **Error handling:** Raw socket operations throw `SocketException` on network failure; Redis client operations throw `RedisConnectionException` or `RedisServerException` with more specific protocol-level detail. Exception handling code should be updated to catch the appropriate StackExchange.Redis exception types.

- **Initialization:** The application must initialize `IConnectionMultiplexer` once at startup and keep it alive for the application lifetime, rather than creating socket instances on demand. This is a best practice for connection pooling but represents a significant architectural change from raw socket usage.
