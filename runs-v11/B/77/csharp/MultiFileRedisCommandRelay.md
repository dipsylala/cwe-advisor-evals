## Verdict

Exploitable.

## Source

User-supplied `noteText` from HTTP form parameter in AnnotationsController.AddAnnotation (line 18, AnnotationsController.cs), and user-controlled `documentId` from URL route parameter. Both flow through AnnotationService.SaveAnnotation to AnnotationCacheClient.StoreAnnotation, where they are incorporated into Redis key and value strings.

## Fix

**Vulnerable code (RedisWireWriter.cs, lines 17-25):**

```csharp
public void SendSetCommand(string key, string value)
{
    string command = "SET " + key + " " + value + "\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);

    NetworkStream stream = _client.GetStream();
    // SAST FINDING: CWE-77 reported here.
    stream.Write(payload, 0, payload.Length);
}
```

**Fixed code (RedisWireWriter.cs, complete replacement):**

```csharp
using StackExchange.Redis;

namespace MultiFileRedisCommandRelay
{
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
}
```

**Library recommendation:** StackExchange.Redis (version from SCA/dependency-check tooling; no specific minimum version required for this API, which has been stable across releases).

## Explanation

The original code hand-builds a Redis inline protocol command by concatenating the key and value directly into a string. If `value` contains `\r\n` (or the Redis command terminator), it becomes multiple commands that the server executes separately. For example, a value of `"test\r\nFLUSHALL\r\n"` causes the server to store part of the string and then execute an unintended FLUSHALL command. The fix replaces the raw socket communication and string concatenation with StackExchange.Redis's `IDatabase.StringSet()` API, which uses the RESP protocol with explicit length-prefix encoding for each argument. This encoding prevents embedded newlines or command delimiters in the value from being interpreted as command boundaries, eliminating the injection vector entirely. The parameterized API is the standard, maintained client library for Redis in .NET and is simpler and safer than hand-building protocol frames.

## Behaviour changes

**Constructor signature change:** The constructor changes from `RedisWireWriter(TcpClient client)` to `RedisWireWriter(IConnectionMultiplexer redis)`. Callers must be updated to pass an IConnectionMultiplexer instance instead of a TcpClient. This is necessary to use StackExchange.Redis's typed API; hand-built protocol frames over raw sockets cannot safely pass untrusted input.

**Removed dependency:** The `using System.Net.Sockets` and `using System.Text` namespaces are no longer needed. The `Encoding.ASCII.GetBytes()` call is removed.

**No visible behaviour change to the caller:** The `SendSetCommand(string key, string value)` method signature and semantics remain the same—it still stores the value under the given key in Redis. The underlying wire protocol changes from the human-readable inline protocol to RESP, but this is transparent to the application; Redis servers support both transparently.

**Removed direct stream access:** The method no longer directly calls `stream.Write()`. Error handling is now delegated to StackExchange.Redis, which throws `RedisConnectionException` on network failures or `RedisServerException` on server errors. Callers should handle these exceptions if different error-recovery logic is needed.
