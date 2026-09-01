## Verdict
**CWE-77: Command Injection** (Confirmed)

Unsanitized user input from the `noteText` HTTP request parameter flows through the call chain to `RedisWireWriter.SendSetCommand()`, where it is concatenated directly into a Redis command string without escaping. An attacker can inject newline characters (`\r\n`) to break out of the SET command and execute arbitrary Redis commands.

**Attack vector**: A user supplies `noteText` containing `\r\nPING\r\n`, which injects a second PING command into the Redis wire stream.

## Source
- **Entry point**: `AnnotationsController.AddAnnotation()` receives `noteText` from HTTP form data
- **Data flow**: `noteText` → `AnnotationService.SaveAnnotation()` → `AnnotationCacheClient.StoreAnnotation()` → `RedisWireWriter.SendSetCommand()`
- **Vulnerable sink**: Line 24 in `RedisWireWriter.cs`, where the unsanitized command is written to the network stream

## Fix

Replace the inline protocol implementation with RESP (Redis Serialization Protocol) encoding, which safely frames commands using length-prefixed arrays:

```csharp
using System.Net.Sockets;
using System.Text;
using System.Collections.Generic;

namespace MultiFileRedisCommandRelay
{
    // Writes commands to a Redis instance using the RESP (Redis Serialization Protocol),
    // which properly frames commands and prevents command injection.
    public class RedisWireWriter
    {
        private readonly TcpClient _client;

        public RedisWireWriter(TcpClient client)
        {
            _client = client;
        }

        public void SendSetCommand(string key, string value)
        {
            // Use RESP protocol to safely encode the SET command.
            // Format: *3\r\n$3\r\nSET\r\n$<key_len>\r\n<key>\r\n$<value_len>\r\n<value>\r\n
            List<string> parts = new List<string> { "SET", key, value };
            byte[] payload = EncodeRespCommand(parts);

            NetworkStream stream = _client.GetStream();
            stream.Write(payload, 0, payload.Length);
        }

        private static byte[] EncodeRespCommand(List<string> parts)
        {
            StringBuilder sb = new StringBuilder();
            
            // RESP array header: *<number_of_elements>\r\n
            sb.AppendFormat("*{0}\r\n", parts.Count);
            
            // Each element: $<length>\r\n<data>\r\n
            foreach (string part in parts)
            {
                byte[] partBytes = Encoding.UTF8.GetBytes(part);
                sb.AppendFormat("${0}\r\n", partBytes.Length);
                sb.Append(part);
                sb.Append("\r\n");
            }
            
            return Encoding.UTF8.GetBytes(sb.ToString());
        }
    }
}
```

## Explanation

**Root cause**: The inline protocol implementation concatenates user-controlled `noteText` directly into command strings. Redis's inline protocol uses CRLF (`\r\n`) as the command terminator, so an attacker can inject these characters to append arbitrary commands to the wire stream. The code has no validation or escaping to prevent this.

**Why this fix works**: RESP (Redis Serialization Protocol) uses length-prefixed encoding for strings (`$<length>\r\n<data>\r\n`). Each command is a properly framed array, so special characters in the key or value cannot be interpreted as command delimiters. The length prefix ensures the Redis parser reads exactly the specified number of bytes, regardless of content. This is the standard, safe way to communicate with Redis and is what all production Redis clients use.

**Defense mechanism**: RESP protocol provides structural defense—command boundaries are encoded in the frame length, not in the delimiter characters, so no escaping logic is needed and no bypass via character encoding is possible.
