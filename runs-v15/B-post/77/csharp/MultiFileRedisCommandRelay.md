## Verdict

exploitable

## Source

User-supplied `noteText` and `documentId` from the ASP.NET Core controller (AnnotationsController.AddAnnotation), which flow through AnnotationService → AnnotationCacheClient → RedisWireWriter.SendSetCommand.

## Fix

**Vulnerable code:**
```csharp
public void SendSetCommand(string key, string value)
{
    string command = "SET " + key + " " + value + "\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);

    NetworkStream stream = _client.GetStream();
    stream.Write(payload, 0, payload.Length);  // Line 24: CWE-77 sink
}
```

**Fixed code:**
```csharp
using StackExchange.Redis;

public class RedisWireWriter
{
    private readonly IDatabase _db;

    public RedisWireWriter(IConnectionMultiplexer redis)
    {
        _db = redis.GetDatabase();
    }

    public void SendSetCommand(string key, string value)
    {
        _db.StringSet(key, value);
    }
}
```

Replace the TcpClient-based initialization in the calling code (AnnotationCacheClient or dependency injection setup) with:
```csharp
var redis = ConnectionMultiplexer.Connect("localhost:6379");
var wireWriter = new RedisWireWriter(redis);
```

## Explanation

The original code builds a raw Redis inline-protocol command by string concatenation. If `key` or `value` contain `\r\n` (carriage return, line feed), they are interpreted as command separators by the Redis server, allowing the injection of arbitrary Redis commands (e.g., `\r\nFLUSHALL\r\n`). The fix replaces the raw socket-based command building with StackExchange.Redis's `IDatabase.StringSet()` method, which uses the RESP wire protocol with explicit length prefixes for each argument, making delimiter injection impossible: untrusted input like `\r\n` is treated as literal data, not as command syntax.

## Behaviour changes

The fixed code replaces raw socket communication with the StackExchange.Redis client library. Differences from the original:

1. **Connection model**: Original uses `TcpClient` + `NetworkStream`; fixed code uses `IConnectionMultiplexer` with automatic connection pooling and reconnection logic.
2. **Command framing**: Original sends inline-protocol commands (plain text, space/newline-delimited); fixed code uses RESP (Redis Serialization Protocol) with length-prefixed arguments.
3. **Error handling**: Original relies on socket operations; fixed code raises `RedisConnectionException` on connection failures and `RedisCommandException` on server-side errors (both inherit from `RedisException`).
4. **Return value**: Original method returns void; fixed `StringSet()` also returns void (no change to caller).
5. **No longer needed imports**: The fixed `RedisWireWriter.cs` no longer needs `System.Net.Sockets` or `System.Text.Encoding`.

None of these differences affect the application logic: the command is still sent to Redis and the key-value pair is still stored. The RESP framing is transparent to the caller, and Redis processes SET commands identically regardless of protocol encoding.
