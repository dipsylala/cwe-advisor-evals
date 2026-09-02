## Verdict

Confirmed command injection vulnerability (CWE-77). User-controlled `documentId` and `noteText` flow through the call chain and are concatenated directly into a Redis command string without proper argument delimiting or escaping. An attacker can inject newline and carriage return characters to break out of the intended command structure and execute arbitrary Redis commands.

## Source

The data flow originates in `AnnotationsController.AddAnnotation()`, where HTTP form parameters `documentId` and `noteText` are accepted from the user. These values flow untouched through:
- `AnnotationService.SaveAnnotation(documentId, noteText)` → stored in `AnnotationRecord`
- `AnnotationCacheClient.StoreAnnotation(record)` → used to construct `key = "annotation:" + record.DocumentId` and `value = record.SavedAtUtc.ToString("O") + "|" + record.Text`
- `RedisWireWriter.SendSetCommand(key, value)` → concatenated into `"SET " + key + " " + value + "\r\n"` at line 19

The sink is line 24, where the unsanitized command string is written to the network stream.

## Fix

Replace the inline protocol implementation with proper RESP (Redis Serialization Protocol) encoding, which uses length-prefixed arguments to safely separate command components:

```csharp
using System.Net.Sockets;
using System.Text;

namespace MultiFileRedisCommandRelay
{
    // Writes commands to a Redis instance using the RESP protocol for safe argument delimiting.
    public class RedisWireWriter
    {
        private readonly TcpClient _client;

        public RedisWireWriter(TcpClient client)
        {
            _client = client;
        }

        public void SendSetCommand(string key, string value)
        {
            // RESP array: *3\r\n (3 arguments: SET, key, value)
            // Each argument prefixed with $<length>\r\n<data>\r\n
            var setCmd = "SET".ToUpper();
            var command = new StringBuilder();
            
            command.Append("*3\r\n");
            AppendRespBulkString(command, setCmd);
            AppendRespBulkString(command, key);
            AppendRespBulkString(command, value);
            
            byte[] payload = Encoding.UTF8.GetBytes(command.ToString());
            NetworkStream stream = _client.GetStream();
            stream.Write(payload, 0, payload.Length);
        }

        private void AppendRespBulkString(StringBuilder sb, string data)
        {
            var bytes = Encoding.UTF8.GetBytes(data);
            sb.Append($"${bytes.Length}\r\n");
            sb.Append(data);
            sb.Append("\r\n");
        }
    }
}
```

## Explanation

The vulnerability exists because the inline protocol relies on whitespace to delimit command arguments. When user input contains `\r\n`, it terminates the current command and allows execution of a new one. For example, if `documentId` is `"doc1\r\nFLUSHALL"`, the resulting string becomes:

```
SET annotation:doc1
FLUSHALL ...
```

The Redis server interprets this as two separate commands, executing both.

The RESP protocol fixes this by using length-prefixed bulk strings: each argument is preceded by `$<byte_length>\r\n`, followed by the exact number of bytes declared. This framing is byte-count based and transparent to special characters—newlines and spaces in the data are treated as literal bytes, not delimiters. An injected `\r\n` becomes part of the data value, not a command terminator.

This approach maintains the same wire protocol without requiring library changes, and properly encodes all user-supplied data so that special characters cannot break out of their intended argument slot.
