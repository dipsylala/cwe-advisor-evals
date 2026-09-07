## Verdict

Command injection vulnerability confirmed. User-controlled `documentId` and `noteText` flow from the HTTP controller through the service layer to `RedisWireWriter.SendSetCommand()`, where they are concatenated directly into a Redis command string without escaping. An attacker can inject newlines (`\r\n`) to execute arbitrary Redis commands.

## Source

The vulnerability spans a four-file call chain:

1. **AnnotationsController.cs, line 18**: `noteText` parameter received from HTTP request (`[FromForm] string noteText`)
2. **AnnotationService.cs, line 15**: `documentId` and `noteText` passed to cache client via `SaveAnnotation()`
3. **AnnotationCacheClient.cs, lines 15-18**: Both values are incorporated into `key = "annotation:" + record.DocumentId` and `value = record.SavedAtUtc.ToString("O") + "|" + record.Text`, then passed to wire writer
4. **RedisWireWriter.cs, line 19**: The sink — `string command = "SET " + key + " " + value + "\r\n"` constructs the command via concatenation, sending unescaped user input to Redis

Attack example: If `documentId = "doc1\r\nFLUSHDB"`, the resulting command becomes:
```
SET annotation:doc1
FLUSHDB
myvalue
```

Redis processes this as two separate commands, executing an unintended FLUSHDB.

## Fix

Replace the plain-text inline protocol with RESP (Redis Serialization Protocol), which handles argument escaping automatically. Rewrite `RedisWireWriter` to construct RESP arrays:

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
            // Use RESP array format: *3\r\n$3\r\nSET\r\n$<keylen>\r\n<key>\r\n$<vallen>\r\n<value>\r\n
            byte[] payload = BuildRespArray(new[] { "SET", key, value });
            NetworkStream stream = _client.GetStream();
            stream.Write(payload, 0, payload.Length);
        }

        private static byte[] BuildRespArray(string[] elements)
        {
            var sb = new StringBuilder();
            sb.Append($"*{elements.Length}\r\n");
            
            foreach (var element in elements)
            {
                byte[] elementBytes = Encoding.UTF8.GetBytes(element);
                sb.Append($"${elementBytes.Length}\r\n");
                sb.Append(element);
                sb.Append("\r\n");
            }

            return Encoding.UTF8.GetBytes(sb.ToString());
        }
    }
}
```

This uses RESP bulk string format (`$<length>\r\n<data>\r\n`) for each argument, ensuring that newlines, spaces, and other special characters in `key` and `value` are treated as literal data, not command delimiters.

## Explanation

CWE-77 (Command Injection) occurs when an interpreter processes untrusted input as part of a command string. Redis's plain-text inline protocol (e.g., `SET key value\r\n`) is vulnerable to injection because newlines terminate commands — any `\r\n` in user data becomes a command boundary.

The RESP format separates commands from data explicitly: the array descriptor (`*3`) declares three elements, and each bulk string (`$<length>`) declares its exact byte length. This means Redis sees the entire content of `key` and `value` as opaque data, regardless of what characters they contain. No escaping or validation of the user input itself is necessary; the protocol structure provides the isolation.

The fix does not require changes to the controller, service, or cache client layers — the vulnerability is isolated to how the wire writer frames the command, and the RESP format is a structural fix that prevents interpretation of special characters in any position of any argument.
