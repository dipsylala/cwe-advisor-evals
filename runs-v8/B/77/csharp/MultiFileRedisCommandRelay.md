## Verdict

Confirmed CWE-77 (Command Injection) in Redis inline-protocol command construction. User-supplied annotation text flows unsanitized into a hand-built Redis command string that is sent over a raw socket, allowing an attacker to inject CRLF sequences to execute arbitrary Redis commands.

## Source

The vulnerability originates from user input:
- **Entry point:** `AnnotationsController.AddAnnotation()` receives `noteText` from HTTP POST form data (`[FromForm] string noteText`)
- **Propagation:** The value flows through `AnnotationService.SaveAnnotation()` → `AnnotationCacheClient.StoreAnnotation()` where it is concatenated into a value string without validation
- **Sink:** `RedisWireWriter.SendSetCommand()` at line 24 concatenates the untrusted value into a Redis command string (`"SET " + key + " " + value + "\r\n"`) and writes it directly to a raw socket via `NetworkStream.Write()`

An attacker can inject payload like:
```
noteText = "test\r\nFLUSHALL\r\n"
```

This produces the command:
```
SET annotation:docId 2026-09-01T12:00:00|test
FLUSHALL

```

The inline Redis protocol interprets the embedded CRLF as a command separator, executing `FLUSHALL` in addition to the intended `SET`.

## Fix

Replace the raw socket command building with StackExchange.Redis's parameterized API. The client library encodes each argument in RESP (Redis Serialization Protocol) with explicit length prefixes, preventing embedded delimiters from being interpreted as command separators.

**Vulnerable code (RedisWireWriter.cs):**
```csharp
using System.Net.Sockets;
using System.Text;

namespace MultiFileRedisCommandRelay
{
    public class RedisWireWriter
    {
        private readonly TcpClient _client;

        public RedisWireWriter(TcpClient client)
        {
            _client = client;
        }

        public void SendSetCommand(string key, string value)
        {
            string command = "SET " + key + " " + value + "\r\n";
            byte[] payload = Encoding.ASCII.GetBytes(command);

            NetworkStream stream = _client.GetStream();
            stream.Write(payload, 0, payload.Length);  // VULNERABLE: line 24
        }
    }
}
```

**Fixed code:**
```csharp
using StackExchange.Redis;

namespace MultiFileRedisCommandRelay
{
    public class RedisWireWriter
    {
        private readonly IConnectionMultiplexer _redis;

        public RedisWireWriter(IConnectionMultiplexer redis)
        {
            _redis = redis;
        }

        public void SendSetCommand(string key, string value)
        {
            IDatabase db = _redis.GetDatabase();
            db.StringSet(key, value);
        }
    }
}
```

Alternatively, if the low-level `Execute()` method is preferred to retain finer protocol control:
```csharp
using StackExchange.Redis;

public void SendSetCommand(string key, string value)
{
    IDatabase db = _redis.GetDatabase();
    db.Execute("SET", new[] { (RedisValue)key, (RedisValue)value });
}
```

## Explanation

The vulnerability stems from hand-building a Redis command string and writing it directly to a raw socket. The Redis inline protocol uses CRLF as the command terminator, so any untrusted data containing newlines or spaces can split the command and inject additional commands. 

The fix replaces the raw socket communication with StackExchange.Redis, which is the standard .NET Redis client library. It encodes each argument using the RESP (Redis Serialization Protocol), which prefixes each argument with its byte length: `$N\r\n<N bytes>\r\n`. This framing means the actual data bytes are never interpreted as delimiters—a value containing `\r\n`, spaces, or Redis command keywords is stored and retrieved as literal data.

The first approach using `StringSet()` is the preferred, type-safe method for SET operations. The second using `Execute()` provides more flexibility if custom Redis commands are needed, but the arguments remain length-delimited and safe from injection.

## Behaviour changes

- **Protocol upgrade:** Switches from the plain-text inline Redis protocol to RESP (Redis Serialization Protocol). All arguments are now length-prefixed and binary-safe, preventing command injection.
- **Interface change:** `RedisWireWriter` constructor now accepts `IConnectionMultiplexer` (StackExchange.Redis connection) instead of a raw `TcpClient`. The caller (AnnotationCacheClient) must be updated to pass a Redis connection.
- **Injection protection:** Values containing `\r\n`, spaces, or command keywords (e.g., `FLUSHALL`, `DEL`) are now treated as literal data, not command separators or new commands.
- **Connection handling:** StackExchange.Redis manages connection pooling, reconnection, and async support automatically. Manual socket management is no longer required.
- **Defense-in-depth:** Consider adding validation to constrain the length and character set of `key` and `value` before passing them to `StringSet()`, though the client library already prevents delimiter injection.
